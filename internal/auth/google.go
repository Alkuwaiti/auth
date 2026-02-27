package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/audit"
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

	socialAccount, err := s.Repo.GetSocialAccountByProviderID(
		ctx,
		domain.ProviderGoogle,
		googleUser.Subject,
	)
	if err == nil {
		user, err := s.Repo.GetUserByEmail(ctx, googleUser.Email)
		if err != nil {
			return TokenPair{}, err
		}
		return s.finalizeLogin(ctx, user, audit.ActionGoogleLogin)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return TokenPair{}, err
	}

	user, err := s.Repo.GetUserByEmail(ctx, googleUser.Email)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return TokenPair{}, err
	}

	if errors.Is(err, domain.ErrNotFound) {
		user, err = s.Repo.CreateUser(ctx, googleUser.Email, nil)
		if err != nil {
			return TokenPair{}, err
		}
	}

	if err = s.Repo.LinkOAuthProvider(ctx, user.ID, domain.ProviderGoogle, googleUser.Subject); err != nil {
		return TokenPair{}, err
	}

	return s.finalizeLogin(ctx, user, audit.ActionGoogleRegisteration)
}
