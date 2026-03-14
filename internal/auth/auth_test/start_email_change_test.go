//go:build integration

package auth_test

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestStartEmailChange_Success(t *testing.T) {
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

	var newEmail string
	err = db.QueryRow(`
		SELECT new_email
		FROM email_change_requests
		WHERE user_id = $1
	`, user.ID).Scan(&newEmail)

	require.NoError(t, err)
	require.Equal(t, "new@example.com", newEmail)
}

func TestStartEmailChange_InvalidEmail(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
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

	err = service.StartEmailChange(ctx, "invalid-email")

	require.ErrorIs(t, err, auth.ErrInvalidEmail)
}

func TestStartEmailChange_EmailUnchanged(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "same@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user.ID)
	ctx = testutil.CtxWithEmail(ctx, "same@example.com")

	err = service.StartEmailChange(ctx, "same@example.com")

	require.ErrorIs(t, err, auth.ErrEmailUnchanged)
}

func TestStartEmailChange_EmailAlreadyInUse(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user1, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "user1@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "user2@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user1.ID)
	ctx = testutil.CtxWithEmail(ctx, "old@example.com")

	err = service.StartEmailChange(ctx, "user2@example.com")

	require.ErrorIs(t, err, auth.ErrEmailAlreadyInUse)
}

func TestStartEmailChange_OutboxEventCreated(t *testing.T) {
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

	var eventType string
	err = db.QueryRow(`
	SELECT event_type
	FROM outbox_events
	WHERE aggregate_id = $1
	  AND event_type = 'user.email.change.request'
`, user.ID.String()).Scan(&eventType)

	require.NoError(t, err)
	require.Equal(t, "user.email.change.request", eventType)
}
