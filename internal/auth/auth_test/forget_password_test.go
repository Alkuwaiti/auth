//go:build integration

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestForgetPassword_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "reset@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	err = service.ForgetPassword(ctx, user.Email)
	require.NoError(t, err)

	var (
		tokenHash  string
		expiresAt  time.Time
		consumedAt *time.Time
	)

	err = db.QueryRow(`
		SELECT token_hash, expires_at, consumed_at
		FROM password_reset_tokens
		WHERE user_id = $1
	`, user.ID).Scan(&tokenHash, &expiresAt, &consumedAt)

	require.NoError(t, err)

	require.NotEmpty(t, tokenHash)
	require.WithinDuration(t, time.Now().Add(20*time.Minute), expiresAt, time.Second)
	require.Nil(t, consumedAt)
}

func TestForgetPassword_ReplacesExistingTokens(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "multi@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	require.NoError(t, service.ForgetPassword(ctx, user.Email))
	require.NoError(t, service.ForgetPassword(ctx, user.Email))

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM password_reset_tokens
		WHERE user_id = $1
	`, user.ID).Scan(&count)

	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestForgetPassword_UserDoesNotExist(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	start := time.Now()
	err := service.ForgetPassword(ctx, "ghost@example.com")
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.GreaterOrEqual(t, elapsed, 150*time.Millisecond)
}
