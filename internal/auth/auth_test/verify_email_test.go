//go:build integration

package auth_test

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestVerifyEmail_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "verify@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	// create token
	raw, hash, err := service.TokenManager.GenerateToken()
	require.NoError(t, err)

	_, err = db.Exec(`
		INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, NOW() + interval '30 minutes')
	`, user.ID, hash)
	require.NoError(t, err)

	err = service.VerifyEmail(ctx, raw)
	require.NoError(t, err)

	// user should now be verified
	var verified bool
	err = db.QueryRow(`
		SELECT is_email_verified FROM users WHERE id = $1
	`, user.ID).Scan(&verified)
	require.NoError(t, err)
	require.True(t, verified)

	// audit log created
	var auditCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM audit_logs 
		WHERE user_id = $1 AND action = 'verify_email'
	`, user.ID).Scan(&auditCount)
	require.NoError(t, err)
	require.Equal(t, 1, auditCount)

	// outbox event created
	var eventCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM outbox_events 
		WHERE aggregate_id = $1 AND event_type = 'user.verified'
	`, user.ID.String()).Scan(&eventCount)
	require.NoError(t, err)
	require.Equal(t, 1, eventCount)
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	err := service.VerifyEmail(ctx, "invalid-token")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidEmailVerificationToken)
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "expired@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	raw, hash, err := service.TokenManager.GenerateToken()
	require.NoError(t, err)

	_, err = db.Exec(`
		INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, NOW() - interval '1 minute')
	`, user.ID, hash)
	require.NoError(t, err)

	err = service.VerifyEmail(ctx, raw)
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidEmailVerificationToken)
}
