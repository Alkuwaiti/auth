package auth

import (
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestChangePassword_Success(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "OldPassword123!", "NewPassword123!")
	require.NoError(t, err)

	// login with old password fails
	_, err = service.Login(ctx, "test@example.com", "OldPassword123!")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)

	// login with new password succeeds
	_, err = service.Login(ctx, "test@example.com", "NewPassword123!")
	require.NoError(t, err)
}

func TestChangePassword_InvalidOldPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "WrongPassword!", "NewPassword123!")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestChangePassword_ReuseOldPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "OldPassword123!", "OldPassword123!")
	require.Error(t, err)
	require.IsType(t, &apperrors.PasswordReuseError{}, err)
}

func TestChangePassword_WeakPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "OldPassword123!", "123")
	require.Error(t, err)
}

func TestChangePassword_UserNotFound(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	err := service.ChangePassword(ctx, uuid.New(), "OldPassword123!", "NewPassword123!")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestChangePassword_CreatesAuditLog(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "OldPassword123!", "NewPassword123!")
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM auth_audit_logs
		WHERE action = 'password_change' AND user_id = $1
	`, user.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestChangePassword_RevokesSessions(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	// login generates a session
	loginTokens, err := service.Login(ctx, "test@example.com", "OldPassword123!")
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "OldPassword123!", "NewPassword123!")
	require.NoError(t, err)

	var revokedAt *time.Time
	err = db.QueryRow(`
		SELECT revoked_at
		FROM sessions
		WHERE refresh_token = $1
	`, loginTokens.RefreshToken).Scan(&revokedAt)
	require.NoError(t, err)
	require.NotNil(t, revokedAt)
}

func TestChangePassword_DeletedUser(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE users
		SET deleted_at = NOW()
		WHERE id = $1
	`, user.ID)
	require.NoError(t, err)

	err = service.ChangePassword(ctx, user.ID, "OldPassword123!", "NewPassword123!")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}
