// Package mfa has mfa logic.
package mfa

import (
	"context"

	"github.com/google/uuid"
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

func (s *service) EnrollMethod(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (MFAMethod, error) {
	if err := methodType.isValid(); err != nil {
		return MFAMethod{}, err
	}

	exists, err := s.methodRepo.UserHasActiveMFAMethod(ctx, userID, methodType)
	if err != nil {
		return MFAMethod{}, err
	}
	if exists {
		return MFAMethod{}, ErrMFAMethodAlreadyEnrolled
	}

	method, err := s.methodRepo.Create(ctx, userID, methodType)
	if err != nil {
		return MFAMethod{}, err
	}

	return method, nil
}
