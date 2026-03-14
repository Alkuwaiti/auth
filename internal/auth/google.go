package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth/domain"
)

func (s *Service) BeginGoogleLogin(ctx context.Context) (string, error) {
	state, err := s.googleProvider.GenerateState()
	if err != nil {
		return "", err
	}

	return s.googleProvider.AuthURL(state), nil
}

func (s *Service) CompleteGoogleLogin(ctx context.Context, code, state string) (TokenPair, error) {
	if err := s.googleProvider.ValidateState(state); err != nil {
		slog.ErrorContext(ctx, "failed to validate state", "err", err)
		return TokenPair{}, err
	}

	googleUser, err := s.googleProvider.ExchangeCode(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "google code exchange failed", "err", err)
		return TokenPair{}, err
	}

	if !googleUser.EmailVerified {
		return TokenPair{}, ErrUnverifiedGoogleEmail
	}

	user, err := s.Repo.GetUserByOAuthProvider(ctx, domain.ProviderGoogle, googleUser.Subject)
	if err == nil {
		return s.finalizeLogin(ctx, user, domain.ActionGoogleLogin, true)
	}

	if !errors.Is(err, domain.ErrNotFound) {
		slog.ErrorContext(ctx, "failed to get user by oauth provider", "err", err)
		return TokenPair{}, err
	}

	user, err = s.Repo.GetUserByEmail(ctx, googleUser.Email)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		slog.ErrorContext(ctx, "failed to get user by email", "err", err)
		return TokenPair{}, err
	}

	if errors.Is(err, domain.ErrNotFound) {
		user, err = s.Repo.CreateUser(ctx, googleUser.Email, nil)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create user", "err", err)
			return TokenPair{}, err
		}
	}

	if err = s.Repo.LinkOAuthProvider(ctx, user.ID, domain.ProviderGoogle, googleUser.Subject); err != nil {
		slog.ErrorContext(ctx, "failed to link oauth provider", "err", err)
		return TokenPair{}, err
	}

	return s.finalizeLogin(ctx, user, domain.ActionGoogleRegisteration, true)
}
