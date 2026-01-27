// Package mfa has mfa logic.
package mfa

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type service struct {
	methodRepo    MFAMethodRepo
	challengeRepo MFAChallengeRepo
	crypto        Crypto
}

// TODO: add tracer here

func NewService(methodRepo MFAMethodRepo, challengeRepo MFAChallengeRepo, crypto Crypto) *service {
	return &service{
		methodRepo:    methodRepo,
		challengeRepo: challengeRepo,
		crypto:        crypto,
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
func (s *service) EnrollMethod(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (EnrollmentResult, error) {
	if !methodType.isValid() {
		return EnrollmentResult{}, &apperrors.ValidationError{
			Field: "method type",
			Msg:   "invalid MFA method type",
		}
	}

	exists, err := s.methodRepo.UserHasActiveMFAMethod(ctx, userID, methodType)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if exists {
		return EnrollmentResult{}, &apperrors.BadRequestError{
			Field: "MFAMethod",
			Msg:   "MFA method already enrolled",
		}
	}

	key, err := totp.Generate(totp.GenerateOpts{
		// TODO: change for config
		Issuer:      "MyApp",
		AccountName: userID.String(),
	})
	if err != nil {
		return EnrollmentResult{}, err
	}

	setupURI := key.URL()

	encryptedSecret, err := s.crypto.Encrypt([]byte(key.Secret()))
	if err != nil {
		return EnrollmentResult{}, err
	}

	method, err := s.methodRepo.Create(ctx, userID, encryptedSecret, methodType)
	if err != nil {
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
	method, err := s.methodRepo.GetByID(ctx, methodID)
	if err != nil {
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

	return s.methodRepo.Confirm(ctx, methodID)
}

func (s *service) GetConfirmedMFAMethodsByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	MFAMethods, err := s.methodRepo.GetConfirmedByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return MFAMethods, nil
}

func (s *service) CreateChallenge(ctx context.Context, userID, methodID uuid.UUID, challengetype ChallengeType) (uuid.UUID, error) {
	c, err := s.challengeRepo.Create(ctx, MFAChallenge{
		MethodID:      methodID,
		UserID:        userID,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		ChallengeType: challengetype,
	})
	if err != nil {
		return uuid.UUID{}, err
	}

	return c.ID, nil
}

func (s *service) GetActiveChallenge(ctx context.Context, challengeID uuid.UUID) (MFAChallenge, error) {
	challenge, err := s.challengeRepo.GetActive(ctx, challengeID)
	if err != nil {
		return MFAChallenge{}, err
	}

	return challenge, nil
}

func (s *service) GetMethodByID(ctx context.Context, methodID uuid.UUID) (MFAMethod, error) {
	method, err := s.methodRepo.GetByID(ctx, methodID)
	if err != nil {
		return MFAMethod{}, err
	}

	return method, nil
}

func (s *service) verifyTOTP(secret, code string) error {
	secretBytes, err := s.crypto.Decrypt([]byte(secret))
	if err != nil {
		return err
	}

	valid, err := totp.ValidateCustom(code, string(secretBytes), time.Now(), totp.ValidateOpts{
		Period: 30,
		Skew:   1, // ±30s
		Digits: otp.DigitsSix,
	})
	if err != nil {
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
	tx, err := s.challengeRepo.BeginTx(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()

	locked, err := s.challengeRepo.LockActiveTOTPChallenge(ctx, tx, challengeID)
	if err != nil {
		return uuid.Nil, err
	}

	if err := s.verifyTOTP(string(locked.SecretCiphertext), code); err != nil {
		return uuid.Nil, err
	}

	if err := s.challengeRepo.ConsumeChallenge(ctx, tx, locked.ChallengeID); err != nil {
		return uuid.Nil, err
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, err
	}

	return locked.UserID, nil
}
