// Package mfa has mfa logic.
package mfa

import (
	"context"
	"encoding/base32"

	"github.com/google/uuid"
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
	if err := methodType.isValid(); err != nil {
		return EnrollmentResult{}, err
	}

	exists, err := s.methodRepo.UserHasActiveMFAMethod(ctx, userID, methodType)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if exists {
		return EnrollmentResult{}, ErrMFAMethodAlreadyEnrolled
	}

	var encryptedSecret []byte
	var setupURI string

	if methodType == MFAMethodTOTP {
		key, err := totp.Generate(totp.GenerateOpts{
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
		return ErrMFAMethodAlreadyConfirmed
	}

	secretBytes, err := s.crypto.Decrypt([]byte(method.Secret))
	if err != nil {
		return err
	}

	valid := totp.Validate(
		code,
		base32.StdEncoding.EncodeToString(secretBytes),
	)
	if !valid {
		return ErrInvalidOTP
	}

	return s.methodRepo.Confirm(ctx, methodID)

}
