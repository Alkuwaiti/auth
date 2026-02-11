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
	"github.com/alkuwaiti/auth/internal/contextkeys"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type EnrollmentResult struct {
	Method   MFAMethod
	SetupURI string
}

// TODO: enroll other methods.
// TODO: make sure to reference the completionist's MFA guide.
func (s *service) EnrollMFAMethod(ctx context.Context, methodType MFAMethodType) (EnrollmentResult, error) {
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
		return EnrollmentResult{}, &apperrors.ValidationError{
			Field: "method type",
			Msg:   "invalid MFA method type",
		}
	}

	exists, err := s.repo.userHasActiveMFAMethodByType(ctx, userID, methodType)
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

	if err = s.repo.deleteExpiredUnconfirmedMethods(ctx, userID, methodType); err != nil {
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

	method, err := s.repo.createUserMFAMethod(ctx, userID, encryptedSecret, methodType)
	if err != nil {
		slog.ErrorContext(ctx, "error when creating a user mfa method", "err", err)
		return EnrollmentResult{}, err
	}

	return EnrollmentResult{
		Method: MFAMethod{
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

	method, err := s.repo.getMFAMethodByID(ctx, methodID)
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

	if err = s.MFAProvider.VerifyTOTP(ctx, method.EncryptedSecret, code); err != nil {
		return nil, err
	}

	if err = s.repo.confirmUserMFAMethod(ctx, tx, methodID); err != nil {
		return nil, err
	}

	if err = s.repo.DeleteBackupCodesForUser(ctx, tx, method.UserID); err != nil {
		return nil, err
	}

	backupCodes, hashed, err := s.MFAProvider.GenerateBackupCodes(10, s.passwords.Hash)
	if err != nil {
		return nil, err
	}

	if err = s.repo.InsertBackupCodes(ctx, tx, method.UserID, hashed); err != nil {
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
	MFAMethodType MFAMethodType
	ExpiresAt     time.Time
}

// TODO: maybe add reason to challenge.
func (s *service) CreateStepUpChallenge(ctx context.Context, methodType MFAMethodType, scope ChallengeScope) (CreateStepUpChallengeResponse, error) {
	ctx, span := tracer.Start(ctx, "AuthService.CreateStepUpChallenge")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return CreateStepUpChallengeResponse{}, err
	}

	method, err := s.repo.getConfirmedMFAMethodByType(ctx, userID, methodType)
	if err != nil {
		return CreateStepUpChallengeResponse{}, err
	}

	challenge, err := s.repo.createChallenge(ctx, MFAChallenge{
		MethodID:      method.ID,
		UserID:        userID,
		Scope:         string(ScopeLogin),
		ChallengeType: ChallengeLogin,
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
	ExpiresIn   time.Time
}

// TODO: add tests
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

	challenge, err := s.repo.getChallengeByID(ctx, challengeID)
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

	token, expiresIn, err := s.tokenManager.GenerateStepUpToken(userID.String(), email, challenge.Scope)
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

// TODO: add backup codes here
func (s *service) verifyAndConsumeChallenge(ctx context.Context, challengeID uuid.UUID, code string) (LockedTOTPChallenge, error) {
	tx, err := s.repo.beginTx(ctx)
	if err != nil {
		return LockedTOTPChallenge{}, err
	}
	defer func() {
		if err = tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.ErrorContext(ctx, "rollback failed", "err", err)
		}
	}()

	lockedChallenge, err := s.repo.lockActiveTOTPChallenge(ctx, tx, challengeID)
	if err != nil {
		if errors.Is(err, ErrInvalidMFAChallenge) {
			return LockedTOTPChallenge{}, &apperrors.InvalidMFACodeError{}
		}
		slog.ErrorContext(ctx, "error locking active totp challenge", "err", err)
		return LockedTOTPChallenge{}, err
	}

	if lockedChallenge.Attempts >= s.Config.MaxChallengeAttempts {
		return LockedTOTPChallenge{}, &apperrors.InvalidMFACodeError{}
	}

	if err = s.MFAProvider.VerifyTOTP(ctx, string(lockedChallenge.SecretCiphertext), code); err != nil {
		if incErr := s.repo.incrementChallengeAttempts(ctx, tx, lockedChallenge.ChallengeID); incErr != nil {
			return LockedTOTPChallenge{}, incErr
		}
		return LockedTOTPChallenge{}, err
	}

	if err = s.repo.consumeChallenge(ctx, tx, lockedChallenge.ChallengeID); err != nil {
		slog.ErrorContext(ctx, "error consuming challenge", "err", err)
		return LockedTOTPChallenge{}, err
	}

	if err = tx.Commit(); err != nil {
		slog.ErrorContext(ctx, "error committing transaction", "err", err)
		return LockedTOTPChallenge{}, err
	}

	return lockedChallenge, nil
}

func (s *service) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := s.repo.userHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
}
