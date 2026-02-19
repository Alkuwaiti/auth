// Package auth handles tokenManager business logic
package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	authz "github.com/alkuwaiti/auth/internal/authorization"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"go.opentelemetry.io/otel"
)

type Service struct {
	Repo         Repo
	Passwords    passwords
	auditor      auditor
	authorizer   authorizer
	Flags        featureFlags
	tokenManager tokenManager
	MFAProvider  MFAProvider
	Config       Config
	Hasher       hasher
}

type Config struct {
	MaxChallengeAttempts int
}

func NewService(repoI Repo, passwords passwords, auditor auditor, authorizer authorizer, flags featureFlags, tokenManager tokenManager, MFAProvider MFAProvider, hasher hasher, Config Config) *Service {
	return &Service{
		Repo:         repoI,
		Passwords:    passwords,
		auditor:      auditor,
		authorizer:   authorizer,
		Flags:        flags,
		tokenManager: tokenManager,
		MFAProvider:  MFAProvider,
		Hasher:       hasher,
		Config:       Config,
	}
}

type Repo interface {
	GetUserBackupCodes(ctx context.Context, userID uuid.UUID) ([]domain.MFABackupCode, error)
	ConsumeBackupCode(ctx context.Context, tx *sql.Tx, codeID uuid.UUID) error
	CreateChallenge(ctx context.Context, challenge domain.MFAChallenge) (domain.MFAChallenge, error)
	GetChallengeByID(ctx context.Context, challengeID uuid.UUID) (domain.MFAChallenge, error)
	LockActiveTOTPChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) (domain.LockedTOTPChallenge, error)
	IncrementChallengeAttempts(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error
	ConsumeChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error
	UserHasActiveMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) (bool, error)
	DeleteExpiredUnconfirmedMethods(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) error
	CreateUserMFAMethod(ctx context.Context, userID uuid.UUID, secret []byte, methodType domain.MFAMethodType) (domain.MFAMethod, error)
	GetMFAMethodByID(ctx context.Context, methodID uuid.UUID) (domain.MFAMethod, error)
	ConfirmUserMFAMethod(ctx context.Context, tx *sql.Tx, methodID uuid.UUID) error
	GetMFAMethodsConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]domain.MFAMethod, error)
	GetConfirmedMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) (domain.MFAMethod, error)
	UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error)
	BeginTx(ctx context.Context) (*sql.Tx, error)
	WithTx(ctx context.Context, fn func(r Repo) error) error
	CreateSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) (domain.Session, error)
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (domain.Session, error)
	RevokeSession(ctx context.Context, SessionID uuid.UUID, revocationReason domain.RevocationReason) error
	UpdatePasswordAndRevokeSessions(ctx context.Context, userID uuid.UUID, newPasswordHash string, reason domain.RevocationReason) error
	RotateSession(ctx context.Context, input domain.RotateSessionInput) error
	RevokeAndMarkSessionsCompromised(ctx context.Context, userID uuid.UUID, reason domain.RevocationReason) error
	DeleteUserAndRevokeSessions(ctx context.Context, userID uuid.UUID, deletionReason domain.DeletionReason, revocationReason domain.RevocationReason) error
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error)
	CreateUser(ctx context.Context, username, email, passwordHash string) (domain.User, error)
	InsertBackupCodes(ctx context.Context, tx *sql.Tx, userID uuid.UUID, hashedCodes []string) error
	DeleteBackupCodesForUser(ctx context.Context, tx *sql.Tx, userID uuid.UUID) error
	CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash string) (uuid.UUID, error)
}

type auditor interface {
	CreateAuditLog(ctx context.Context, input audit.CreateAuditLogInput) error
}

type passwords interface {
	Validate(password string) error
	Hash(password string) (string, error)
	Compare(hash string, password string) (bool, error)
}

type authorizer interface {
	CanWithRoles(roles []string, cap authz.Capability) bool
}

type featureFlags interface {
	RefreshTokensEnabled(ctx context.Context) bool
}

type tokenManager interface {
	GenerateAccessToken(roles []string, userID, email string) (string, error)
	GenerateSecureToken() (string, error)
	GenerateStepUpToken(userID, email, scope string) (string, int, error)
}

type MFAProvider interface {
	GenerateTOTPKey(email string) (*otp.Key, error)
	GenerateEncryptedSecret(key *otp.Key) ([]byte, error)
	VerifyTOTP(ctx context.Context, secret, code string) (bool, error)
	GenerateBackupCodes(n int, hash func(string) (string, error)) (plain []string, hashed []string, err error)
}

type hasher interface {
	Hash(input string) string
	Compare(hashedInput, input string) bool
}

// TODO: test race condition for all of these methods.

var tracer = otel.Tracer("auth-service/auth")
