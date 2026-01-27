package auth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alkuwaiti/auth/internal/audit"
	authz "github.com/alkuwaiti/auth/internal/authorization"
	"github.com/alkuwaiti/auth/internal/crypto"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/flags"
	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/alkuwaiti/auth/internal/password"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/alkuwaiti/auth/internal/tokens"
	"github.com/stretchr/testify/require"
)

// setupTestAuthService spins up a test DB, runs migrations, and returns a ready service.
// The caller must call cleanup() at the end.
func setupTestAuthService(t *testing.T) (*service, *sql.DB, func()) {
	t.Helper() // marks this as a helper for better test output

	ctx := context.Background()

	testDB, err := testutil.NewPostgres(ctx)
	require.NoError(t, err)

	err = testutil.RunMigrations(testDB.DB, "../db/migrations")
	require.NoError(t, err)

	passwordService := password.NewService(12)

	queries := postgres.New(testDB.DB)

	auditRepo := audit.NewRepo(queries)

	auditService := audit.New(auditRepo)

	authorizerService := authz.New()

	flagsService := flags.New(flags.Config{
		RefreshTokensEnabled: true,
	})

	authRepo := NewRepo(testDB.DB)

	tokenManager := tokens.New(tokens.Config{
		Issuer:   "auth-service",
		Audience: "auth-service",
		JWTKey:   []byte("any random jwt key doesn't really matter or at least i think it doesn't matter"),
	})

	methodRepo := mfa.NewMFAMethodRepo(queries)

	challengeRepo := mfa.NewMFAChallengeRepo(testDB.DB)

	c := crypto.NewAESCrypto([]byte("some key"))

	multifactor := mfa.NewService(*methodRepo, *challengeRepo, c)

	service := NewService(authRepo, passwordService, auditService, authorizerService, flagsService, tokenManager, multifactor)

	cleanup := func() {
		_ = testDB.DB.Close()
		_ = testDB.Terminate(ctx)
	}

	return service, testDB.DB, cleanup
}
