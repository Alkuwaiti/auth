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

func (s *service) EnrollMethod(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (EnrollmentResult, error) {
	var err error
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

	var (
		encryptedSecret []byte
		setupURI        string
	)

	if methodType == MFAMethodTOTP {
		var key *otp.Key
		key, err = totp.Generate(totp.GenerateOpts{
			// TODO: change for config
			Issuer:      "MyApp",
			AccountName: userID.String(),
		})
		if err != nil {
			return EnrollmentResult{}, err
		}

		setupURI = key.URL()

		encryptedSecret, err = s.crypto.Encrypt([]byte(key.Secret()))
		if err != nil {
			return EnrollmentResult{}, err
		}
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

	secretBytes, err := s.crypto.Decrypt([]byte(method.Secret))
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

	return s.methodRepo.Confirm(ctx, methodID)
}
