//go:build integration

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func Test_RegisterUser_Success(t *testing.T) {
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

	var (
		email        string
		passwordHash string
		isActive     bool
	)

	err = db.QueryRow(`
		SELECT email, password_hash, is_active
		FROM users
		WHERE email = $1
	`, input.Email).Scan(&email, &passwordHash, &isActive)

	require.NoError(t, err)
	require.Equal(t, input.Email, email)
	require.NotEmpty(t, passwordHash)
	require.True(t, isActive)
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
	require.IsType(t, err, &apperrors.BadRequestError{})
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
	require.IsType(t, err, &apperrors.BadRequestError{})
}

func TestRegisterUser_Success_AuditTrail(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	var auditLog struct {
		Action    string
		UserID    uuid.UUID
		CreatedAt time.Time
	}

	err = db.QueryRow(`
		SELECT action, user_id, created_at
		FROM auth_audit_logs
		WHERE action = $1 AND user_id = $2
	`, audit.ActionCreateUser, user.ID).
		Scan(&auditLog.Action, &auditLog.UserID, &auditLog.CreatedAt)

	require.NoError(t, err)
	require.Equal(t, string(audit.ActionCreateUser), auditLog.Action)
	require.Equal(t, user.ID, auditLog.UserID)
	require.False(t, auditLog.CreatedAt.IsZero())
}
