// Package mfa has mfa logic.
package mfa

import (
	"context"

	"github.com/google/uuid"
)

type Service struct {
	methodRepo    MFAMethodRepo
	challengeRepo MFAChallengeRepo
}

func (s *Service) EnrollMethod(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (MFAMethod, error) {
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
