//go:build integration

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestChangePassword(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   bool
		oldPassword string
		newPassword string
		deleteUser  bool
		expectedErr error
		checkLogin  bool
	}{
		{
			name:        "Success",
			setupUser:   true,
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword123!",
			expectedErr: nil,
			checkLogin:  true,
		},
		{
			name:        "InvalidOldPassword",
			setupUser:   true,
			oldPassword: "WrongPassword!",
			newPassword: "NewPassword123!",
			expectedErr: &apperrors.InvalidCredentialsError{},
		},
		{
			name:        "ReuseOldPassword",
			setupUser:   true,
			oldPassword: "OldPassword123!",
			newPassword: "OldPassword123!",
			expectedErr: &apperrors.PasswordReuseError{},
		},
		{
			name:        "WeakPassword",
			setupUser:   true,
			oldPassword: "OldPassword123!",
			newPassword: "123",
			expectedErr: &apperrors.ValidationError{},
		},
		{
			name:        "UserNotFound",
			setupUser:   false,
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword123!",
			expectedErr: &apperrors.InvalidCredentialsError{},
		},
		{
			name:        "DeletedUser",
			setupUser:   true,
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword123!",
			deleteUser:  true,
			expectedErr: &apperrors.InvalidCredentialsError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, db, cleanup := setupTestAuthService(t)
			defer cleanup()

			ctx := context.Background()
			ctx = testutil.CtxWithRequestMeta(ctx)

			var userID uuid.UUID
			if tt.setupUser {
				user, err := service.RegisterUser(ctx, RegisterUserInput{
					Username: "testUser",
					Email:    "test@example.com",
					Password: "OldPassword123!",
				})
				require.NoError(t, err)
				userID = user.ID

				ctx = testutil.CtxWithUserID(ctx, user.ID)

				if tt.deleteUser {
					_, err = db.Exec(`
						UPDATE users
						SET deleted_at = NOW()
						WHERE id = $1
					`, userID)
					require.NoError(t, err)
				}
			}

			err := service.ChangePassword(ctx, tt.oldPassword, tt.newPassword)

			if tt.expectedErr != nil {
				require.Error(t, err)
				require.IsType(t, tt.expectedErr, err)
			} else {
				require.NoError(t, err)

				if tt.checkLogin {
					// login with old password fails
					_, err = service.Login(ctx, "test@example.com", "OldPassword123!")
					require.Error(t, err)
					require.IsType(t, &apperrors.InvalidCredentialsError{}, err)

					// login with new password succeeds
					_, err = service.Login(ctx, "test@example.com", tt.newPassword)
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestChangePassword_CreatesAuditLog(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user.ID)

	err = service.ChangePassword(ctx, "OldPassword123!", "NewPassword123!")
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
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user.ID)

	// login generates a session
	res, err := service.Login(ctx, "test@example.com", "OldPassword123!")
	require.NoError(t, err)

	err = service.ChangePassword(ctx, "OldPassword123!", "NewPassword123!")
	require.NoError(t, err)

	var revokedAt *time.Time
	err = db.QueryRow(`
		SELECT revoked_at
		FROM sessions
		WHERE refresh_token = $1
	`, res.Tokens.RefreshToken).Scan(&revokedAt)
	require.NoError(t, err)
	require.NotNil(t, revokedAt)
}
