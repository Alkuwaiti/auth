// Package flags provides system level flags.
package flags

import "context"

type flagsProvider struct {
	config Config
}

type Config struct {
	RefreshTokensEnabled bool
}

func New(config Config) *flagsProvider {
	return &flagsProvider{
		config: config,
	}
}

func (s *flagsProvider) RefreshTokensEnabled(ctx context.Context) bool {
	return s.config.RefreshTokensEnabled
}
