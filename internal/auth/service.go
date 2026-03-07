// Package auth handles tokenManager business logic
package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	googlesocial "github.com/alkuwaiti/auth/internal/social/google"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"go.opentelemetry.io/otel"
)

type Service struct {
	Repo           Repo
	Passwords      passwords
	auditor        auditor
	Flags          featureFlags
	TokenManager   tokenManager
	MFAProvider    MFAProvider
	googleProvider googleProvider
	Config         Config
}

type Config struct {
	MaxChallengeAttempts int
}

func NewService(repoI Repo, passwords passwords, auditor auditor, flags featureFlags, tokenManager tokenManager, MFAProvider MFAProvider, googleProvider googleProvider, Config Config) *Service {
	return &Service{
		Repo:           repoI,
		Passwords:      passwords,
		auditor:        auditor,
		Flags:          flags,
		TokenManager:   tokenManager,
		MFAProvider:    MFAProvider,
		googleProvider: googleProvider,
		Config:         Config,
	}
}

type Repo interface {
	GetUserBackupCodes(ctx context.Context, userID uuid.UUID) ([]domain.MFABackupCode, error)
	ConsumeBackupCode(ctx context.Context, codeID uuid.UUID) error
	CreateChallenge(ctx context.Context, challenge domain.MFAChallenge) (domain.MFAChallenge, error)
	GetChallengeByID(ctx context.Context, challengeID uuid.UUID) (domain.MFAChallenge, error)
	GetActiveTOTPChallengeForUpdate(ctx context.Context, challengeID uuid.UUID) (domain.ActiveTOTPChallenge, error)
	IncrementChallengeAttempts(ctx context.Context, challengeID uuid.UUID) error
	ConsumeChallenge(ctx context.Context, challengeID uuid.UUID) error
	UserHasActiveMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) (bool, error)
	CreateUserMFAMethod(ctx context.Context, userID uuid.UUID, secret []byte, methodType domain.MFAMethodType) (domain.MFAMethod, error)
	GetUserMFAMethodByID(ctx context.Context, methodID, userID uuid.UUID) (domain.MFAMethod, error)
	ConfirmUserMFAMethod(ctx context.Context, methodID uuid.UUID) error
	GetMFAMethodsConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]domain.MFAMethod, error)
	GetConfirmedMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) (domain.MFAMethod, error)
	UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error)
	WithTx(ctx context.Context, fn func(r Repo) error) error
	CreateSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) (domain.Session, error)
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (domain.Session, error)
	RevokeSession(ctx context.Context, SessionID uuid.UUID, revocationReason domain.RevocationReason) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error
	RevokeSessions(ctx context.Context, userID uuid.UUID, revocationReason domain.RevocationReason) error
	DeleteUser(ctx context.Context, userID uuid.UUID, deletionReason domain.DeletionReason) error
	MarkSessionsCompromised(ctx context.Context, userID uuid.UUID) error
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error)
	CreateUser(ctx context.Context, email string, passwordHash *string) (domain.User, error)
	InsertBackupCodes(ctx context.Context, userID uuid.UUID, hashedCodes []string) error
	DeleteUserBackupCodes(ctx context.Context, userID uuid.UUID) error
	CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash string) (uuid.UUID, string, error)
	CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash string, ExpiresAt time.Time) error
	ConsumeEmailVerificationToken(ctx context.Context, tokenHash string) (uuid.UUID, error)
	VerifyUserEmail(ctx context.Context, userID uuid.UUID) (string, error)
	InvalidateEmailVerificationTokens(ctx context.Context, userID uuid.UUID) error
	GetUserByOAuthProvider(ctx context.Context, provider domain.Provider, providerUserID string) (domain.User, error)
	LinkOAuthProvider(ctx context.Context, userID uuid.UUID, provider domain.Provider, providerUserID string) error
	CreateOutboxEvent(ctx context.Context, outboxEvent domain.OutboxEvent) error
	ListPasskeysByUserID(ctx context.Context, userID uuid.UUID) ([][]byte, error)
	CreateWebAuthnChallenge(ctx context.Context, challenge []byte, userID uuid.UUID, expiresAt time.Time) error
	GetWebAuthnChallengeByUserID(ctx context.Context, userID uuid.UUID) ([]byte, error)
}

type auditor interface {
	CreateAuditLog(ctx context.Context, input audit.CreateAuditLogInput) error
}

type passwords interface {
	Validate(password string) error
	Hash(password string) (string, error)
	Compare(hash string, password string) (bool, error)
}

type featureFlags interface {
	RefreshTokensEnabled(ctx context.Context) bool
}

type tokenManager interface {
	GenerateAccessToken(roles []string, userID, email string) (string, error)
	GenerateToken() (raw string, hash string, err error)
	GenerateStepUpToken(userID, email, scope string) (string, int, error)
	Hash(input string) string
	Compare(hashedInput, input string) bool
}

type MFAProvider interface {
	GenerateTOTPKey(email string) (*otp.Key, error)
	GenerateEncryptedSecret(key *otp.Key) ([]byte, error)
	VerifyTOTP(ctx context.Context, secret, code string) (bool, error)
	GenerateBackupCodes(n int, hash func(string) (string, error)) (plain []string, hashed []string, err error)
}

type googleProvider interface {
	GenerateState() (string, error)
	ValidateState(state string) error
	AuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (googlesocial.GoogleUser, error)
}

// TODO: test race condition for all of these methods.

var tracer = otel.Tracer("auth-service/auth")
