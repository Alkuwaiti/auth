// Package mfa has mfa logic.
package mfa

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

type service struct {
	MFARepo MFARepo
	crypto  Crypto
	Config  Config
}

var tracer = otel.Tracer("auth-service/mfa")

func NewService(MFARepo MFARepo, crypto Crypto, config Config) *service {
	return &service{
		MFARepo: MFARepo,
		crypto:  crypto,
		Config:  config,
	}
}

type Crypto interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type EnrollmentResult struct {
	Method   MFAMethod
	SetupURI string
}

// TODO: enroll other methods.
func (s *service) EnrollMethod(ctx context.Context, userID uuid.UUID, email string, methodType MFAMethodType) (EnrollmentResult, error) {
	ctx, span := tracer.Start(ctx, "mfaService.EnrollMethod")
	defer span.End()

	if !methodType.isValid() {
		return EnrollmentResult{}, &apperrors.ValidationError{
			Field: "method type",
			Msg:   "invalid MFA method type",
		}
	}

	exists, err := s.MFARepo.userHasActiveMFAMethodByType(ctx, userID, methodType)
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

	if err = s.MFARepo.DeleteExpiredUnconfirmedMethods(ctx, userID, methodType); err != nil {
		return EnrollmentResult{}, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.Config.AppName,
		AccountName: email,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "totp generation failed")
		slog.ErrorContext(ctx, "error generating totp", "err", err)
		return EnrollmentResult{}, err
	}

	setupURI := key.URL()

	encryptedSecret, err := s.crypto.Encrypt([]byte(key.Secret()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "error encrypting")
		slog.ErrorContext(ctx, "error when encrypting secret", "err", err)
		return EnrollmentResult{}, err
	}

	method, err := s.MFARepo.createUserMFAMethod(ctx, userID, encryptedSecret, methodType)
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

func (s *service) ConfirmMethod(ctx context.Context, methodID uuid.UUID, code string) error {
	ctx, span := tracer.Start(ctx, "mfaService.ConfirmMethod")
	defer span.End()

	method, err := s.MFARepo.getMFAMethodByID(ctx, methodID)
	if err != nil {
		slog.ErrorContext(ctx, "error when getting mfa method by id", "err", err)
		return err
	}

	if method.ExpiresAt != nil && method.ExpiresAt.Before(time.Now()) {
		span.SetStatus(codes.Error, "method expired")
		return &apperrors.BadRequestError{
			Field: "method",
			Msg:   "enrollment window expired",
		}
	}

	if method.ConfirmedAt != nil {
		span.SetStatus(codes.Error, "method confirmed")
		return &apperrors.BadRequestError{
			Field: "method",
			Msg:   "already confirmed",
		}
	}

	if err := s.verifyTOTP(ctx, method.Secret, code); err != nil {
		return err
	}

	if err := s.MFARepo.confirmUserMFAMethod(ctx, methodID); err != nil {
		return err
	}

	return nil
}

func (s *service) GetConfirmedMFAMethodsByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	MFAMethods, err := s.MFARepo.getMFAMethodsConfirmedByUser(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "error when getting mfa methods confirmed by user id", "err", err)
		return nil, err
	}

	return MFAMethods, nil
}

// TODO: figure out how to target which method type when creating a challenge.
// TODO: add rate limiting
func (s *service) CreateChallenge(ctx context.Context, userID, methodID uuid.UUID, challengetype ChallengeType, scope ChallengeScope) (MFAChallenge, error) {
	if ok := challengetype.isValid(); !ok {
		return MFAChallenge{}, ErrInvalidMFAChallengeType
	}

	if ok := scope.isValid(); !ok {
		return MFAChallenge{}, ErrInvalidMFAChallengeScope
	}

	challenge, err := s.MFARepo.createChallenge(ctx, MFAChallenge{
		MethodID:      methodID,
		UserID:        userID,
		Scope:         string(scope),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		ChallengeType: challengetype,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error creating challenge", "err", err)
		return MFAChallenge{}, err
	}

	return challenge, nil
}

func (s *service) GetMethodByID(ctx context.Context, methodID uuid.UUID) (MFAMethod, error) {
	method, err := s.MFARepo.getMFAMethodByID(ctx, methodID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting method by id", "err", err)
		return MFAMethod{}, err
	}

	return method, nil
}

func (s *service) GetChallengeByID(ctx context.Context, challengeID uuid.UUID) (MFAChallenge, error) {
	challenge, err := s.MFARepo.getChallengeByID(ctx, challengeID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting challenge by id", "err", err)
		return MFAChallenge{}, err
	}

	return challenge, nil
}

func (s *service) GetConfirmedMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (MFAMethod, error) {
	method, err := s.MFARepo.GetConfirmedMFAMethodByType(ctx, userID, methodType)
	if err != nil {
		slog.ErrorContext(ctx, "error getting confirmed mfa methods by type", "err", err)
		return MFAMethod{}, err
	}

	return method, nil
}

func (s *service) verifyTOTP(ctx context.Context, secret, code string) error {
	ctx, span := tracer.Start(ctx, "mfaService.verifyTOTP")
	defer span.End()

	secretBytes, err := s.crypto.Decrypt([]byte(secret))
	if err != nil {
		slog.ErrorContext(ctx, "error decrypting", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "error encrypting")
		return err
	}

	valid, err := totp.ValidateCustom(code, string(secretBytes), time.Now(), totp.ValidateOpts{
		Period: 30,
		Skew:   1, // ±30s
		Digits: otp.DigitsSix,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error validating totp", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "error validating totp")
		return err
	}

	if !valid {
		return &apperrors.BadRequestError{
			Field: "code",
			Msg:   "invalid code",
		}
	}

	return nil
}

func (s *service) VerifyAndConsumeChallenge(ctx context.Context, challengeID uuid.UUID, code string) (VerifiedChallenge, error) {
	tx, err := s.MFARepo.beginTx(ctx)
	if err != nil {
		return VerifiedChallenge{}, err
	}
	defer func() {
		if err = tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.ErrorContext(ctx, "rollback failed", "err", err)
		}
	}()

	locked, err := s.MFARepo.lockActiveTOTPChallenge(ctx, tx, challengeID)
	if err != nil {
		if errors.Is(err, ErrInvalidMFAChallenge) {
			return VerifiedChallenge{}, &apperrors.InvalidMFACodeError{}
		}

		slog.ErrorContext(ctx, "error locking active totp challenge", "err", err)
		return VerifiedChallenge{}, err
	}

	if locked.Attempts >= s.Config.MaxChallengeAttempts {
		return VerifiedChallenge{}, &apperrors.InvalidMFACodeError{}
	}

	if err := s.verifyTOTP(ctx, string(locked.SecretCiphertext), code); err != nil {
		if incErr := s.MFARepo.incrementChallengeAttempts(ctx, tx, locked.ChallengeID); incErr != nil {
			return VerifiedChallenge{}, incErr
		}
		return VerifiedChallenge{}, err
	}

	if err := s.MFARepo.consumeChallenge(ctx, tx, locked.ChallengeID); err != nil {
		slog.ErrorContext(ctx, "error consuming challenge", "err", err)
		return VerifiedChallenge{}, err
	}

	if err := tx.Commit(); err != nil {
		slog.ErrorContext(ctx, "error committing transaction", "err", err)
		return VerifiedChallenge{}, err
	}

	return VerifiedChallenge{
		ChallengeID: locked.ChallengeID,
		UserID:      locked.UserID,
		MethodID:    locked.MethodID,
	}, nil
}

func (s *service) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := s.MFARepo.userHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
}
