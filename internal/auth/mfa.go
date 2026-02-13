package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/contextkeys"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type EnrollmentResult struct {
	Method   domain.MFAMethod
	SetupURI string
}

// TODO: enroll other methods.
// TODO: make sure to reference the completionist's MFA guide.
func (s *service) EnrollMFAMethod(ctx context.Context, methodType domain.MFAMethodType) (EnrollmentResult, error) {
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

	if err = methodType.Validate(); err != nil {
		return EnrollmentResult{}, &apperrors.ValidationError{
			Field: "method type",
			Msg:   "invalid MFA method type",
		}
	}

	exists, err := s.repoI.UserHasActiveMFAMethodByType(ctx, userID, methodType)
	if err != nil {
		slog.ErrorContext(ctx, "error when checking if user has an active MFA method", "user_id", userID, "method_type", methodType, "err", err)
		return EnrollmentResult{}, err
	}
	if exists {
		return EnrollmentResult{}, &apperrors.BadRequestError{
			Field: "MFAMethod",
			Msg:   "MFA method already enrolled",
		}
	}

	if err = s.repoI.DeleteExpiredUnconfirmedMethods(ctx, userID, methodType); err != nil {
		return EnrollmentResult{}, err
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

	method, err := s.repoI.CreateUserMFAMethod(ctx, userID, encryptedSecret, methodType)
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

func (s *service) ConfirmMFAMethod(ctx context.Context, methodID uuid.UUID, code string) (backupCodes []string, err error) {
	ctx, span := tracer.Start(ctx, "AuthService.ConfirmMFAMethod")
	defer span.End()

	code = strings.TrimSpace(code)

	method, err := s.repoI.GetMFAMethodByID(ctx, methodID)
	if err != nil {
		return nil, err
	}

	if method.ExpiresAt != nil && method.ExpiresAt.Before(time.Now()) {
		return nil, &apperrors.BadRequestError{
			Field: "method",
			Msg:   "enrollment window expired",
		}
	}

	if method.ConfirmedAt != nil {
		return nil, &apperrors.BadRequestError{
			Field: "method",
			Msg:   "already confirmed",
		}
	}

	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return nil, err
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	totpValid, err := s.MFAProvider.VerifyTOTP(ctx, method.EncryptedSecret, code)
	if err != nil {
		return nil, err
	}
	if !totpValid {
		return nil, &apperrors.InvalidMFACodeError{}
	}

	if err = s.repoI.ConfirmUserMFAMethod(ctx, tx, methodID); err != nil {
		return nil, err
	}

	if err = s.repo.DeleteBackupCodesForUser(ctx, tx, method.UserID); err != nil {
		return nil, err
	}

	backupCodes, hashed, err := s.MFAProvider.GenerateBackupCodes(10, s.passwords.Hash)
	if err != nil {
		return nil, err
	}

	slog.DebugContext(ctx, "where are my backup codes? ", "backupCodes", backupCodes)

	if err = s.repo.insertBackupCodes(ctx, tx, method.UserID, hashed); err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	committed = true

	meta := contextkeys.RequestMetaFromContext(ctx)
	_ = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID: &method.UserID,
		Action: audit.ActionConfirmMFAMethod,
		Context: audit.AuditContext{
			"method_type": "totp",
			"method_id":   methodID.String(),
		},
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	})

	return backupCodes, nil
}

func (s *service) CompleteLoginMFA(ctx context.Context, challengeID uuid.UUID, code string) (TokenPair, error) {
	lockedChallenge, err := s.verifyAndConsumeChallenge(ctx, challengeID, code)
	if err != nil {
		return TokenPair{}, err
	}

	user, err := s.repo.getUserByID(ctx, lockedChallenge.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "user_id", lockedChallenge.UserID, "err", err)
		return TokenPair{}, err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)
	if err := s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID: &user.ID,
		Action: audit.ActionConfirmMFAMethod,
		Context: audit.AuditContext{
			"method_type": "totp",
			"method_id":   challengeID.String(),
		},
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		return TokenPair{}, err
	}

	return s.finalizeLogin(ctx, user, audit.ActionLoginMFA)
}

type CreateStepUpChallengeResponse struct {
	ChallengeID   uuid.UUID
	MFAMethodType domain.MFAMethodType
	ExpiresAt     time.Time
}

func (s *service) CreateStepUpChallenge(ctx context.Context, methodType domain.MFAMethodType, scope domain.ChallengeScope) (CreateStepUpChallengeResponse, error) {
	ctx, span := tracer.Start(ctx, "AuthService.CreateStepUpChallenge")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return CreateStepUpChallengeResponse{}, err
	}

	method, err := s.repoI.GetConfirmedMFAMethodByType(ctx, userID, methodType)
	if err != nil {
		return CreateStepUpChallengeResponse{}, err
	}

	challenge, err := s.repoI.CreateChallenge(ctx, domain.MFAChallenge{
		MethodID:      method.ID,
		UserID:        userID,
		Scope:         domain.ScopeLogin,
		ChallengeType: domain.ChallengeStepUp,
	})
	if err != nil {
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

func (s *service) VerifyStepUpChallenge(ctx context.Context, challengeID uuid.UUID, code string) (VerifyStepUpChallengeResponse, error) {
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

	challenge, err := s.repoI.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return VerifyStepUpChallengeResponse{}, err
	}

	if challenge.UserID != userID {
		slog.WarnContext(ctx, "challenge does not belong to user", "user_id", userID, "err", err)
		return VerifyStepUpChallengeResponse{}, &apperrors.ForbiddenError{}
	}

	if challenge.ExpiresAt.Before(time.Now()) {
		return VerifyStepUpChallengeResponse{}, &apperrors.BadRequestError{
			Field: "challenge",
			Msg:   "challenge expired",
		}
	}

	if challenge.ConsumedAt != nil {
		return VerifyStepUpChallengeResponse{}, &apperrors.BadRequestError{
			Field: "challenge",
			Msg:   "challenge already consumed",
		}
	}

	_, err = s.verifyAndConsumeChallenge(ctx, challengeID, code)
	if err != nil {
		return VerifyStepUpChallengeResponse{}, err
	}

	token, expiresIn, err := s.tokenManager.GenerateStepUpToken(userID.String(), email, challenge.Scope.String())
	if err != nil {
		slog.ErrorContext(ctx, "error generating step up token", "err", err)
		return VerifyStepUpChallengeResponse{}, err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)
	if err := s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID: &challenge.UserID,
		Action: audit.ActionConfirmMFAMethod,
		Context: audit.AuditContext{
			"method_type": "totp",
			"method_id":   challengeID.String(),
		},
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
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

// TODO: probably need to still break this up.
func (s *service) verifyAndConsumeChallenge(ctx context.Context, challengeID uuid.UUID, code string) (domain.LockedTOTPChallenge, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return domain.LockedTOTPChallenge{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	challenge, err := s.repoI.LockActiveTOTPChallenge(ctx, tx, challengeID)
	if err != nil {
		if errors.Is(err, ErrInvalidMFAChallenge) {
			return domain.LockedTOTPChallenge{}, &apperrors.InvalidMFACodeError{}
		}
		return domain.LockedTOTPChallenge{}, err
	}

	if challenge.Attempts >= s.Config.MaxChallengeAttempts {
		return domain.LockedTOTPChallenge{}, &apperrors.InvalidMFACodeError{}
	}

	totpValid, err := s.MFAProvider.VerifyTOTP(ctx, string(challenge.SecretCiphertext), code)
	if err != nil {
		return domain.LockedTOTPChallenge{}, err
	}

	backupCodeValid, err := s.verifyBackupCode(ctx, tx, challenge.UserID, code)
	if err != nil {
		return domain.LockedTOTPChallenge{}, err
	}

	if !totpValid && !backupCodeValid {
		if err = s.repoI.IncrementChallengeAttempts(ctx, tx, challenge.ChallengeID); err != nil {
			return domain.LockedTOTPChallenge{}, err
		}

		if err = tx.Commit(); err != nil {
			return domain.LockedTOTPChallenge{}, err
		}

		return domain.LockedTOTPChallenge{}, &apperrors.InvalidMFACodeError{}
	}

	if err = s.repoI.ConsumeChallenge(ctx, tx, challenge.ChallengeID); err != nil {
		return domain.LockedTOTPChallenge{}, err
	}

	if err = tx.Commit(); err != nil {
		return domain.LockedTOTPChallenge{}, err
	}

	return challenge, nil
}

func (s *service) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := s.repoI.UserHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (s *service) verifyBackupCode(ctx context.Context, tx *sql.Tx, userID uuid.UUID, code string) (bool, error) {
	code = strings.ToUpper(strings.TrimSpace(code))

	if len(code) != 9 || code[4] != '-' {
		return false, nil
	}

	codes, err := s.repoI.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, c := range codes {
		ok, err := s.passwords.Compare(c.CodeHash, code)
		if err != nil {
			return false, err
		}

		if ok {
			if err := s.repoI.ConsumeBackupCode(ctx, tx, c.ID); err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}
