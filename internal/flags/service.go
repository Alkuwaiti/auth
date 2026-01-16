// Package flags provides system level flags.
package flags

import "context"

type service struct {
	config Config
}

type Config struct {
	RefreshTokensEnabled bool
}

func New(config Config) *service {
	return &service{
		config: config,
	}
}

func (s *service) RefreshTokensEnabled(ctx context.Context) bool {
	return s.config.RefreshTokensEnabled
}
