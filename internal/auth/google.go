package auth

import (
	"context"
	"log/slog"
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
		slog.ErrorContext(ctx, "error exchanging code", "err", err)
		return TokenPair{}, err
	}

	slog.InfoContext(ctx, "this is the user", "user", googleUser)

	return TokenPair{}, nil
}
