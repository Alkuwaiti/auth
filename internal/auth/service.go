// Package auth handles tokenManager business logic
package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	authz "github.com/alkuwaiti/auth/internal/authorization"
	"github.com/pquerna/otp"
	"go.opentelemetry.io/otel"
)

type service struct {
	repo         *repo
	passwords    passwords
	auditor      auditor
	authorizer   authorizer
	flags        featureFlags
	tokenManager tokenManager
	MFAProvider  MFAProvider
	Config       Config
}

type Config struct {
	MaxChallengeAttempts int
}

func NewService(repo *repo, passwords passwords, auditor auditor, authorizer authorizer, flags featureFlags, tokenManager tokenManager, MFAProvider MFAProvider, Config Config) *service {
	return &service{
		repo:         repo,
		passwords:    passwords,
		auditor:      auditor,
		authorizer:   authorizer,
		flags:        flags,
		tokenManager: tokenManager,
		MFAProvider:  MFAProvider,
		Config:       Config,
	}
}

type auditor interface {
	CreateAuditLog(ctx context.Context, input audit.CreateAuditLogInput) error
}

type passwords interface {
	Validate(password string) error
	Hash(password string) (string, error)
	Compare(hash string, password string) error
}

type authorizer interface {
	CanWithRoles(roles []string, cap authz.Capability) bool
}

type featureFlags interface {
	RefreshTokensEnabled(ctx context.Context) bool
}

type tokenManager interface {
	GenerateAccessToken(roles []string, userID, email string) (string, error)
	GenerateRefreshToken() (string, error)
	GenerateStepUpToken(userID, email, scope string) (string, time.Time, error)
}

type MFAProvider interface {
	GenerateTOTPKey(email string) (*otp.Key, error)
	GenerateEncryptedSecret(key *otp.Key) ([]byte, error)
	VerifyTOTP(ctx context.Context, secret, code string) error
	GenerateBackupCodes(n int, hash func(string) (string, error)) (plain []string, hashed []string, err error)
}

// TODO: test race condition for all of these methods.

var tracer = otel.Tracer("auth-service/auth")
