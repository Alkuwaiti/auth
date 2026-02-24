package auth

import (
	"context"
	"errors"

	"github.com/alkuwaiti/auth/internal/auth/domain"
)

func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	hashedToken := s.TokenManager.Hash(rawToken)

	if err := s.Repo.WithTx(ctx, func(r Repo) error {
		userID, err := r.ConsumeEmailVerificationToken(ctx, hashedToken)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrInvalidEmailVerificationToken
			}
			return err
		}

		if err = r.VerifyUserEmail(ctx, userID); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
