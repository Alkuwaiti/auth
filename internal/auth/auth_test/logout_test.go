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

func TestLogout_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	err = service.Logout(ctx, res.Tokens.RefreshToken)
	require.NoError(t, err)

	hashedToken := service.TokenManager.Hash(res.Tokens.RefreshToken)
	var revokedAt *time.Time
	err = db.QueryRow(`
		SELECT revoked_at
		FROM sessions
		WHERE refresh_token = $1
	`, hashedToken).Scan(&revokedAt)

	require.NoError(t, err)
	require.NotNil(t, revokedAt)
}

func TestLogout_Idempotent(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	err := service.Logout(ctx, "non-existent-refresh-token")
	require.NoError(t, err)
}

func TestLogout_PreventsRefreshReuse(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	err = service.Logout(ctx, res.Tokens.RefreshToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestLogout_CreatesAuditLog(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	err = service.Logout(ctx, res.Tokens.RefreshToken)
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM audit_logs
		WHERE action = 'logout'
	`).Scan(&count)

	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestLogout_MultiDeviceIsolation(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	ctx1 := testutil.CtxWithRequestMeta(ctx)
	ctx2 := testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx1, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	device1, err := service.Login(ctx1, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	device2, err := service.Login(ctx2, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	err = service.Logout(ctx1, device1.Tokens.RefreshToken)
	require.NoError(t, err)

	hashedToken1 := service.TokenManager.Hash(device1.Tokens.RefreshToken)
	// device 1 revoked
	var revokedCount int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE refresh_token = $1 AND revoked_at IS NOT NULL
	`, hashedToken1).Scan(&revokedCount)

	require.NoError(t, err)
	require.Equal(t, 1, revokedCount)

	hashedToken2 := service.TokenManager.Hash(device2.Tokens.RefreshToken)
	// device 2 still active
	var activeCount int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE refresh_token = $1 AND revoked_at IS NULL
	`, hashedToken2).Scan(&activeCount)

	require.NoError(t, err)
	require.Equal(t, 1, activeCount)
}
