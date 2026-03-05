//go:build integration

package auth_test

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestCreateEmailVerificationToken_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "request@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	err = service.CreateEmailVerificationToken(ctx, user.Email)
	require.NoError(t, err)

	// token should exist
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM email_verification_tokens 
		WHERE user_id = $1
	`, user.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// outbox event created
	err = db.QueryRow(`
		SELECT COUNT(*) FROM outbox_events 
		WHERE aggregate_id = $1 AND event_type = 'user.verification.requested'
	`, user.ID.String()).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestCreateEmailVerificationToken_UserNotFound(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	err := service.CreateEmailVerificationToken(ctx, "unknown@example.com")
	require.NoError(t, err)
}

func TestCreateEmailVerificationToken_AlreadyVerified(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "verified@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE users SET is_email_verified = true WHERE id = $1
	`, user.ID)
	require.NoError(t, err)

	err = service.CreateEmailVerificationToken(ctx, user.Email)
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM email_verification_tokens 
		WHERE user_id = $1
	`, user.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count)
}
