//go:build integration

package auth

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/user"
	"github.com/stretchr/testify/require"
)

func TestRegisterUser_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	input := RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	}

	_, err := service.RegisterUser(ctx, input)
	require.NoError(t, err)

	userService := user.NewTestUserService(db)

	user, err := userService.GetUserByEmail(ctx, input.Email)

	require.NoError(t, err)
	require.Equal(t, input.Email, user.Email)
	require.NotEmpty(t, user.PasswordHash)
}

func TestRegisterUser_Fail_DuplicateEmail(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	// register again with same email
	_, err = service.RegisterUser(ctx, RegisterUserInput{
		Username: "anotherUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})

	require.Error(t, err)
	require.ErrorIs(t, err, &apperrors.InvalidCredentialsError{})
}

func TestRegisterUser_Fail_DuplicateUsername(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	// register again with same email
	_, err = service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "anothermail@example.com",
		Password: "StrongPassword123!",
	})

	require.Error(t, err)
	require.ErrorIs(t, err, &apperrors.InvalidCredentialsError{})
}

func TestRegisterUser_Success_AuditTrail(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	auditService := audit.NewTestAuditService(db)

	auditLog, err := auditService.GetAuditLogByUserID(ctx, user.ID)
	require.NoError(t, err)

	require.Equal(t, string(audit.ActionCreateUser), auditLog.Action)
	require.Equal(t, user.ID, auditLog.UserID)
	require.NotEmpty(t, auditLog.CreatedAt)
}
