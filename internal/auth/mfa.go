package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/passwords"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type EnrollmentResult struct {
	Method   domain.MFAMethod
	SetupURI string
}

// TODO: enroll other methods.

func (s *Service) EnrollMFAMethod(ctx context.Context, methodType domain.MFAMethodType) (EnrollmentResult, error) {
	ctx, span := tracer.Start(ctx, "AuthService.EnrollMethod")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return EnrollmentResult{}, err
	}

	userEmail, err := contextkeys.UserEmailFromContext(ctx)
	if err != nil {
		return EnrollmentResult{}, err
	}

	if !methodType.IsValid() {
		return EnrollmentResult{}, ErrInvalidMFAMethodType
	}

	key, err := s.MFAProvider.GenerateTOTPKey(userEmail)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "totp generation failed")
		slog.ErrorContext(ctx, "error generating totp", "err", err)
		return EnrollmentResult{}, err
	}

	setupURI := key.URL()

	encryptedSecret, err := s.MFAProvider.GenerateEncryptedSecret(key)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "error encrypting")
		slog.ErrorContext(ctx, "error when encrypting secret", "err", err)
		return EnrollmentResult{}, err
	}

	expiresAt := time.Now().Add(5 * time.Minute)
	method, err := s.Repo.CreateUserMFAMethod(ctx, domain.MFAMethod{
		UserID:          userID,
		EncryptedSecret: string(encryptedSecret),
		Type:            methodType,
		ExpiresAt:       &expiresAt,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error when creating a user mfa method", "err", err)
		return EnrollmentResult{}, err
	}

	return EnrollmentResult{
		Method: domain.MFAMethod{
			ID:        method.ID,
			Type:      method.Type,
			CreatedAt: method.CreatedAt,
		},
		SetupURI: setupURI,
	}, nil
}

func (s *Service) ConfirmMFAMethod(ctx context.Context, methodID uuid.UUID, code string) (backupCodes []string, err error) {
	ctx, span := tracer.Start(ctx, "AuthService.ConfirmMFAMethod")
	defer span.End()

	code = strings.TrimSpace(code)

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	method, err := s.Repo.GetUserMFAMethodByID(ctx, methodID, userID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting mfa method by id", "err", err, "method_id", methodID)
		return nil, err
	}

	if method.ExpiresAt != nil && method.ExpiresAt.Before(time.Now()) {
		slog.DebugContext(ctx, "method expired", "method_id", methodID)
		return nil, ErrMFAMethodExpired
	}

	if method.ConfirmedAt != nil {
		slog.DebugContext(ctx, "method already confirmed", "method_id", methodID)
		return nil, ErrMethodAlreadyConfirmed
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		totpValid, totpErr := s.MFAProvider.VerifyTOTP(ctx, method.EncryptedSecret, code)
		if totpErr != nil {
			return totpErr
		}
		if !totpValid {
			return ErrInvalidMFACode
		}

		if err = r.ConfirmUserMFAMethod(ctx, methodID); err != nil {
			slog.ErrorContext(ctx, "error confirming user mfa method", "err", err, "method_id", methodID)
			return err
		}

		if err = r.DeleteUserBackupCodes(ctx, method.UserID); err != nil {
			slog.ErrorContext(ctx, "error deleting backup codes for user", "err", err, "method_id", methodID)
			return err
		}

		var hashed []string
		backupCodes, hashed, err = s.MFAProvider.GenerateBackupCodes(10, passwords.Hash)
		if err != nil {
			slog.ErrorContext(ctx, "error generating backup codes", "err", err, "method_id", methodID)
			return err
		}

		if err = r.InsertBackupCodes(ctx, method.UserID, hashed); err != nil {
			slog.ErrorContext(ctx, "error inserting backup codes", "err", err, "method_id", methodID)
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)
	if err = s.Repo.CreateAuditLog(ctx, domain.CreateAuditLogInput{
		UserID: &method.UserID,
		Action: domain.ActionConfirmMFAMethod,
		Context: domain.AuditContext{
			"method_type": "totp",
			"method_id":   methodID.String(),
		},
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		return nil, err
	}

	return backupCodes, nil
}

func (s *Service) CompleteLoginMFA(ctx context.Context, challengeID uuid.UUID, code string) (TokenPair, error) {
	challenge, err := s.VerifyAndConsumeChallenge(ctx, challengeID, code)
	if err != nil {
		return TokenPair{}, err
	}

	user, err := s.Repo.GetUserByID(ctx, challenge.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return TokenPair{}, ErrInvalidCredentials
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "user_id", challenge.UserID, "err", err)
		return TokenPair{}, err
	}

	return s.finalizeLogin(ctx, user, domain.ActionLoginMFA, challenge.RememberMe)
}

type CreateStepUpChallengeResponse struct {
	ChallengeID   uuid.UUID
	MFAMethodType domain.MFAMethodType
	ExpiresAt     time.Time
}

func (s *Service) CreateStepUpChallenge(ctx context.Context, methodType domain.MFAMethodType, scope domain.ChallengeScope) (CreateStepUpChallengeResponse, error) {
	ctx, span := tracer.Start(ctx, "AuthService.CreateStepUpChallenge")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return CreateStepUpChallengeResponse{}, err
	}

	method, err := s.Repo.GetConfirmedMFAMethodByType(ctx, userID, methodType)
	if err != nil {
		slog.ErrorContext(ctx, "error getting confirmed mfa methods by type", "err", err)
		return CreateStepUpChallengeResponse{}, err
	}

	challenge, err := s.Repo.CreateChallenge(ctx, domain.MFAChallenge{
		MethodID:      method.ID,
		UserID:        userID,
		Scope:         domain.ScopeLogin,
		ChallengeType: domain.ChallengeStepUp,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error creating challenge", "err", err)
		return CreateStepUpChallengeResponse{}, err
	}

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
	)

	span.SetStatus(codes.Ok, "created step up challenge")

	return CreateStepUpChallengeResponse{
		ChallengeID:   challenge.ID,
		MFAMethodType: methodType,
		ExpiresAt:     challenge.ExpiresAt,
	}, nil
}

type VerifyStepUpChallengeResponse struct {
	StepUpToken string
	ExpiresIn   int
}

func (s *Service) VerifyStepUpChallenge(ctx context.Context, challengeID uuid.UUID, code string) (VerifyStepUpChallengeResponse, error) {
	ctx, span := tracer.Start(ctx, "AuthService.VerifyStepUpChallenge")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return VerifyStepUpChallengeResponse{}, err
	}

	email, err := contextkeys.UserEmailFromContext(ctx)
	if err != nil {
		return VerifyStepUpChallengeResponse{}, err
	}

	challenge, err := s.Repo.GetChallengeByID(ctx, challengeID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting challenge by id", "err", err)
		return VerifyStepUpChallengeResponse{}, err
	}

	if challenge.UserID != userID {
		slog.WarnContext(ctx, "challenge does not belong to user", "user_id", userID)
		return VerifyStepUpChallengeResponse{}, ErrForbidden
	}

	if challenge.ExpiresAt.Before(time.Now()) {
		slog.DebugContext(ctx, "challenge expired", "user_id", userID)
		return VerifyStepUpChallengeResponse{}, ErrChallengeExpired
	}

	if challenge.ConsumedAt != nil {
		slog.DebugContext(ctx, "challenge consumed", "user_id", userID)
		return VerifyStepUpChallengeResponse{}, ErrChallengeConsumed
	}

	_, err = s.VerifyAndConsumeChallenge(ctx, challengeID, code)
	if err != nil {
		return VerifyStepUpChallengeResponse{}, err
	}

	token, expiresIn, err := s.TokenManager.GenerateStepUpToken(userID.String(), email, challenge.Scope.String())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "error generating step-up token")
		slog.ErrorContext(ctx, "error generating step up token", "err", err)
		return VerifyStepUpChallengeResponse{}, err
	}

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
	)

	span.SetStatus(codes.Ok, "verified step up challenge")

	return VerifyStepUpChallengeResponse{
		StepUpToken: token,
		ExpiresIn:   expiresIn,
	}, nil
}

func (s *Service) VerifyAndConsumeChallenge(ctx context.Context, challengeID uuid.UUID, code string) (domain.ActiveTOTPChallenge, error) {
	var (
		challenge domain.ActiveTOTPChallenge
		err       error
	)

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		challenge, err = r.GetActiveTOTPChallengeForUpdate(ctx, challengeID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrInvalidMFACode
			}
			slog.ErrorContext(ctx, "error locking active totp challenge", "err", err)
			return err
		}

		if challenge.Attempts >= s.Config.MaxChallengeAttempts {
			slog.DebugContext(ctx, "max challenge attempts reached")
			return ErrInvalidMFACode
		}

		totpValid, totpErr := s.MFAProvider.VerifyTOTP(ctx, string(challenge.SecretCiphertext), code)
		if totpErr != nil {
			return totpErr
		}

		backupCodeValid, verificationErr := s.VerifyBackupCode(ctx, r, challenge.UserID, code)
		if verificationErr != nil {
			return verificationErr
		}

		if !totpValid && !backupCodeValid {
			if err = r.IncrementChallengeAttempts(ctx, challenge.ChallengeID); err != nil {
				slog.ErrorContext(ctx, "error incrementing challenge attempts", "err", err)
				return err
			}

			return ErrInvalidMFACode
		}

		if err = r.ConsumeChallenge(ctx, challenge.ChallengeID); err != nil {
			slog.ErrorContext(ctx, "error consuming challenge", "err", err)
			return err
		}

		return nil
	}); err != nil {
		return domain.ActiveTOTPChallenge{}, err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)
	if err := s.Repo.CreateAuditLog(ctx, domain.CreateAuditLogInput{
		UserID: &challenge.UserID,
		Action: domain.ActionConsumeChallenge,
		Context: domain.AuditContext{
			"method_type":  "totp",
			"challenge_id": challengeID.String(),
		},
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		return domain.ActiveTOTPChallenge{}, err
	}

	return challenge, nil
}

func (s *Service) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := s.Repo.UserHasActiveMFAMethod(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "error checking if user has active mfa method", "err", err)
		return false, err
	}

	return exists, nil
}

func (s *Service) VerifyBackupCode(ctx context.Context, r Repo, userID uuid.UUID, code string) (bool, error) {
	code = strings.ToUpper(strings.TrimSpace(code))

	if len(code) != 9 || code[4] != '-' {
		return false, nil
	}

	codes, err := r.GetUserBackupCodes(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting user backup codes", "err", err)
		return false, err
	}

	for _, c := range codes {
		if s.TokenManager.Compare(c.CodeHash, code) {
			if err := r.ConsumeBackupCode(ctx, c.ID); err != nil {
				slog.ErrorContext(ctx, "error consuming backup code", "err", err, "challenge_id", c.ID)
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}
