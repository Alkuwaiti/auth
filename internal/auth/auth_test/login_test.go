//go:build integration

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/flags"
	"github.com/stretchr/testify/require"
)

func TestLogin_Success(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!", false)
	require.NoError(t, err)

	require.NotEmpty(t, res.Tokens.AccessToken)
	require.NotEmpty(t, res.Tokens.RefreshToken)
	require.NotZero(t, res.Tokens.RefreshExpiresAt)
	require.NotZero(t, res.Tokens.UserID)
}

func TestLogin_InvalidEmail(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.Login(ctx, "doesnotexist@example.com", "whatever", false)

	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestLogin_InvalidPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "CorrectPassword123!",
	})
	require.NoError(t, err)

	_, err = service.Login(ctx, "test@example.com", "WrongPassword!", false)

	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestLogin_InactiveUser(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE users SET is_active = false WHERE id = $1
	`, user.ID)
	require.NoError(t, err)

	_, err = service.Login(ctx, "test@example.com", "StrongPassword123!", false)

	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestLogin_CreatesSession(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = service.Login(ctx, "test@example.com", "StrongPassword123!", false)
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

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	_, err = service.Login(ctx, "test@example.com", "StrongPassword123!", false)
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM audit_logs 
		WHERE user_id = $1 AND action = 'login'
	`, user.ID).Scan(&count)

	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestLogin_DeletedUser(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	email := "test@example.com"
	password := "OldPassword123!"

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE users
		SET deleted_at = NOW()
		WHERE id = $1
	`, user.ID)
	require.NoError(t, err)

	_, err = service.Login(ctx, email, password, false)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestLogin_Disabled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	flagsService := flags.New(flags.Config{
		RefreshTokensEnabled: false,
	})

	svc := &auth.Service{
		Flags: flagsService,
	}

	_, err := svc.Login(ctx, "some_email", "some_password", false)

	require.Error(t, err)

	require.ErrorIs(t, err, auth.ErrRefreshDisabled)
}

func TestLogin_RememberMe_False_Sets7DayExpiry(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	before := time.Now()

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!", false)
	require.NoError(t, err)

	after := time.Now()

	expectedMin := before.Add(7 * 24 * time.Hour)
	expectedMax := after.Add(7 * 24 * time.Hour)

	require.True(t,
		res.Tokens.RefreshExpiresAt.After(expectedMin) &&
			res.Tokens.RefreshExpiresAt.Before(expectedMax),
		"expected refresh expiry to be ~7 days",
	)
}

func TestLogin_RememberMe_True_Sets30DayExpiry(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	before := time.Now()

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!", true)
	require.NoError(t, err)

	after := time.Now()

	expectedMin := before.Add(30 * 24 * time.Hour)
	expectedMax := after.Add(30 * 24 * time.Hour)

	require.True(t,
		res.Tokens.RefreshExpiresAt.After(expectedMin) &&
			res.Tokens.RefreshExpiresAt.Before(expectedMax),
		"expected refresh expiry to be ~30 days",
	)
}
