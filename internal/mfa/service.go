// Package mfa has mfa logic.
package mfa

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type service struct {
	MFARepo MFARepo
	crypto  Crypto
	Config  Config
}

// TODO: add tracer here
// TODO: add logs

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
	if !methodType.isValid() {
		return EnrollmentResult{}, &apperrors.ValidationError{
			Field: "method type",
			Msg:   "invalid MFA method type",
		}
	}

	exists, err := s.MFARepo.userHasActiveMFAMethod(ctx, userID, methodType)
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

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.Config.AppName,
		AccountName: email,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error generating totp", "err", err)
		return EnrollmentResult{}, err
	}

	setupURI := key.URL()

	encryptedSecret, err := s.crypto.Encrypt([]byte(key.Secret()))
	if err != nil {
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
	method, err := s.MFARepo.getMFAMethodByID(ctx, methodID)
	if err != nil {
		slog.ErrorContext(ctx, "error when getting mfa method by id", "err", err)
		return err
	}

	if method.ConfirmedAt != nil {
		return &apperrors.BadRequestError{
			Field: "method",
			Msg:   "already confirmed",
		}
	}

	if err := s.verifyTOTP(method.Secret, code); err != nil {
		return err
	}

	return s.MFARepo.confirmUserMFAMethod(ctx, methodID)
}

func (s *service) GetConfirmedMFAMethodsByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	MFAMethods, err := s.MFARepo.getMFAMethodsConfirmedByUser(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "error when getting mfa methods confirmed by user id", "err", err)
		return nil, err
	}

	return MFAMethods, nil
}

func (s *service) CreateChallenge(ctx context.Context, userID, methodID uuid.UUID, challengetype ChallengeType) (uuid.UUID, error) {
	c, err := s.MFARepo.createChallenge(ctx, MFAChallenge{
		MethodID:      methodID,
		UserID:        userID,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		ChallengeType: challengetype,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error when creating challenge", "err", err)
		return uuid.UUID{}, err
	}

	return c.ID, nil
}

func (s *service) GetActiveChallenge(ctx context.Context, challengeID uuid.UUID) (MFAChallenge, error) {
	challenge, err := s.MFARepo.getActiveChallenge(ctx, challengeID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting active challenge", "err", err)
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

func (s *service) verifyTOTP(secret, code string) error {
	secretBytes, err := s.crypto.Decrypt([]byte(secret))
	if err != nil {
		slog.Error("error decrypting", "err", err)
		return err
	}

	valid, err := totp.ValidateCustom(code, string(secretBytes), time.Now(), totp.ValidateOpts{
		Period: 30,
		Skew:   1, // ±30s
		Digits: otp.DigitsSix,
	})
	if err != nil {
		slog.Error("error validating secret", "err", err)
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

func (s *service) VerifyAndConsumeChallenge(ctx context.Context, challengeID uuid.UUID, code string) (uuid.UUID, error) {
	tx, err := s.MFARepo.beginTx(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()

	locked, err := s.MFARepo.lockActiveTOTPChallenge(ctx, tx, challengeID)
	if err != nil {
		if errors.Is(err, ErrInvalidMFAChallenge) {
			return uuid.Nil, &apperrors.InvalidMFACodeError{}
		}

		slog.ErrorContext(ctx, "error locking active totp challenge", "err", err)
		return uuid.Nil, err
	}

	if err := s.verifyTOTP(string(locked.SecretCiphertext), code); err != nil {
		return uuid.Nil, err
	}

	if err := s.MFARepo.consumeChallenge(ctx, tx, locked.ChallengeID); err != nil {
		slog.ErrorContext(ctx, "error consuming challenge", "err", err)
		return uuid.Nil, err
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, err
	}

	return locked.UserID, nil
}
