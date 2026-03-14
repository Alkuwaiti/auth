//go:build integration

package auth_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestConfirmEmailChange_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "old@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user.ID)
	ctx = testutil.CtxWithEmail(ctx, "old@example.com")

	err = service.StartEmailChange(ctx, "new@example.com")
	require.NoError(t, err)

	// get token from outbox
	var payload []byte
	err = db.QueryRow(`
		SELECT payload
		FROM outbox_events
		WHERE aggregate_id = $1
	  	AND event_type = 'user.email.change.request'
	`, user.ID.String()).Scan(&payload)
	require.NoError(t, err)

	var event struct {
		Token string `json:"token"`
	}

	err = json.Unmarshal(payload, &event)
	require.NoError(t, err)

	err = service.ConfirmEmailChange(ctx, event.Token)
	require.NoError(t, err)

	// email updated
	var email string
	err = db.QueryRow(`
		SELECT email
		FROM users
		WHERE id = $1
	`, user.ID).Scan(&email)

	require.NoError(t, err)
	require.Equal(t, "new@example.com", email)

	// request deleted
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM email_change_requests
		WHERE user_id = $1
	`, user.ID).Scan(&count)

	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestConfirmEmailChange_InvalidToken(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	err := service.ConfirmEmailChange(ctx, "invalid-token")

	require.ErrorIs(t, err, auth.ErrInvalidEmailChangeToken)
}

func TestConfirmEmailChange_ExpiredToken(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "old@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user.ID)
	ctx = testutil.CtxWithEmail(ctx, "old@example.com")

	err = service.StartEmailChange(ctx, "new@example.com")
	require.NoError(t, err)

	rawToken := "test-token"
	hashed := service.TokenManager.Hash(rawToken)

	_, err = db.Exec(`
		UPDATE email_change_requests
		SET token_hash = $1, expires_at = NOW() - INTERVAL '1 minute'
		WHERE user_id = $2
	`, hashed, user.ID)
	require.NoError(t, err)

	err = service.ConfirmEmailChange(ctx, rawToken)

	require.ErrorIs(t, err, auth.ErrInvalidEmailChangeToken)
}
