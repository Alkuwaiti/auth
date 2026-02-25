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

func TestResetPassword_InvalidToken(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	err := service.ResetPassword(ctx, "invalid-token", "NewPassword123!")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidResetToken)
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Username: "expired",
		Email:    "expired@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	rawToken := "expired-token"
	hashed := service.TokenManager.Hash(rawToken)

	_, err = db.Exec(`
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, user.ID, hashed, time.Now().Add(-1*time.Minute))
	require.NoError(t, err)

	err = service.ResetPassword(ctx, rawToken, "NewPassword123!")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidResetToken)
}

func TestResetPassword_TokenCannotBeReused(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Username: "reuse",
		Email:    "reuse@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	rawToken := "reuse-token"
	hashed := service.TokenManager.Hash(rawToken)

	_, err = db.Exec(`
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, user.ID, hashed, time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	require.NoError(t, service.ResetPassword(ctx, rawToken, "NewPassword123!"))

	err = service.ResetPassword(ctx, rawToken, "AnotherPassword123!")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidResetToken)
}
