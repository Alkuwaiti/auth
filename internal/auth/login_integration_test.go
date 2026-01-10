//go:build integration

package auth

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/stretchr/testify/require"
)

func TestLogin_Success(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	tokens, err := service.Login(ctx, LoginInput{
		Email:     "test@example.com",
		Password:  "StrongPassword123!",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	require.NoError(t, err)

	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	require.NotZero(t, tokens.RefreshExpiresAt)
	require.NotZero(t, tokens.UserID)
}

func TestLogin_InvalidEmail(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.Login(ctx, LoginInput{
		Email:     "doesnotexist@example.com",
		Password:  "whatever",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})

	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestLogin_InvalidPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "CorrectPassword123!",
	})
	require.NoError(t, err)

	_, err = service.Login(ctx, LoginInput{
		Email:     "test@example.com",
		Password:  "WrongPassword!",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})

	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestLogin_InactiveUser(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE users SET is_active = false WHERE id = $1
	`, user.ID)
	require.NoError(t, err)

	_, err = service.Login(ctx, LoginInput{
		Email:     "test@example.com",
		Password:  "StrongPassword123!",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})

	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestLogin_CreatesSession(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = service.Login(ctx, LoginInput{
		Email:     "test@example.com",
		Password:  "StrongPassword123!",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM sessions WHERE user_id = $1
	`, user.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestLogin_CreatesAuditLog(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = service.Login(ctx, LoginInput{
		Email:     "test@example.com",
		Password:  "StrongPassword123!",
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM auth_audit_logs 
		WHERE user_id = $1 AND action = 'login'
	`, user.ID).Scan(&count)

	require.NoError(t, err)
	require.Equal(t, 1, count)
}
