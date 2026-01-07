package testutil

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/password"
	"github.com/alkuwaiti/auth/internal/user"
	"github.com/stretchr/testify/require"
)

// SetupTestService spins up a test DB, runs migrations, and returns a ready service.
// The caller must call cleanup() at the end.
func SetupTestService(t *testing.T) (*auth.Service, *sql.DB, func()) {
	t.Helper() // marks this as a helper for better test output

	ctx := context.Background()

	testDB, err := NewPostgres(ctx)
	require.NoError(t, err)

	err = runMigrations(testDB.DB, "../db/migrations")
	require.NoError(t, err)

	userRepo := user.NewRepo(postgres.New(testDB.DB))

	userService := user.NewService(userRepo)

	passwordService := password.NewService(12)

	auditRepo := audit.NewRepo(postgres.New(testDB.DB))

	auditService := audit.NewService(auditRepo)

	authRepo := auth.NewRepo(testDB.DB)
	service := auth.NewService(authRepo, userService, passwordService, auditService, auth.Config{
		Issuer:   "auth-service",
		Audience: "auth-service",
		JWTKey:   []byte("any random jwt key doesn't really matter or at least i think it doesn't matter"),
	})

	cleanup := func() {
		_ = testDB.DB.Close()
		_ = testDB.Terminate(ctx)
	}

	return service, testDB.DB, cleanup
}

func NewTestUserService(db *sql.DB) *user.Service {
	userRepo := user.NewRepo(postgres.New(db))
	return user.NewService(userRepo)
}
