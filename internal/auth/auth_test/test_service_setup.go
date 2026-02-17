// Package auth is where all test cases are kept.
package auth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/repository"
	authz "github.com/alkuwaiti/auth/internal/authorization"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/flags"
	"github.com/alkuwaiti/auth/internal/hasher"
	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/alkuwaiti/auth/internal/password"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/alkuwaiti/auth/internal/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// setupTestAuthService spins up a test DB, runs migrations, and returns a ready service.
// The caller must call cleanup() at the end.
func setupTestAuthService(t *testing.T) (*auth.Service, *sql.DB, func()) {
	t.Helper() // marks this as a helper for better test output

	ctx := context.Background()

	testDB, err := testutil.NewPostgres(ctx)
	require.NoError(t, err)

	err = testutil.RunMigrations(testDB.DB, "../../db/migrations")
	require.NoError(t, err)

	passwordService := password.NewService(12)

	queries := postgres.New(testDB.DB)

	auditRepo := audit.NewRepo(queries)

	auditService := audit.New(auditRepo)

	authorizerService := authz.New()

	flagsService := flags.New(flags.Config{
		RefreshTokensEnabled: true,
	})

	authRepo := repository.NewRepo(testDB.DB)

	tokenManager := tokens.New(tokens.Config{
		Issuer:   "auth-service",
		Audience: "auth-service",
		JWTKey:   []byte("any random jwt key doesn't really matter or at least i think it doesn't matter"),
	})

	multifactor := mfa.NewService(&noopCrypto{}, mfa.Config{
		AppName: "MyApp",
	})

	hasher := hasher.NewHasher()

	service := auth.NewService(authRepo, passwordService, auditService, authorizerService, flagsService, tokenManager, multifactor, hasher, auth.Config{
		MaxChallengeAttempts: 5,
	})

	cleanup := func() {
		_ = testDB.DB.Close()
		_ = testDB.Terminate(ctx)
	}

	return service, testDB.DB, cleanup
}

type noopCrypto struct{}

func (c *noopCrypto) Encrypt(b []byte) ([]byte, error) {
	// just return the bytes as-is
	return b, nil
}

func (c *noopCrypto) Decrypt(b []byte) ([]byte, error) {
	// just return the bytes as-is
	return b, nil
}

func seedUser(t *testing.T, db *sql.DB, userID uuid.UUID, email string, ctx context.Context) {
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, email, password_hash, created_at)
		VALUES ($1, $2, $3, $4, now())
	`,
		userID,
		"username",
		email,
		"password_hash",
	)
	require.NoError(t, err)
}
