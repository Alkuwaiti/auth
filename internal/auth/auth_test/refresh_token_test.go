//go:build integration

package auth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/flags"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestRefreshToken_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	refreshed, err := service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.NoError(t, err)

	require.NotEmpty(t, refreshed.AccessToken)
	require.NotEmpty(t, refreshed.RefreshToken)
	require.NotEqual(t, res.Tokens.RefreshToken, refreshed.RefreshToken)
	require.Equal(t, res.Tokens.UserID, refreshed.UserID)

	hashedToken := service.TokenManager.Hash(res.Tokens.RefreshToken)
	// old session revoked
	var revokedAt *time.Time
	err = db.QueryRow(`
		SELECT revoked_at
		FROM sessions
		WHERE refresh_token = $1
	`, hashedToken).Scan(&revokedAt)
	require.NoError(t, err)
	require.NotNil(t, revokedAt)

	hashedToken = service.TokenManager.Hash(refreshed.RefreshToken)
	// new session exists
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE refresh_token = $1
	`, hashedToken).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RefreshToken(ctx, "non-existent-token")
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_ExpiredSession(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	hashedToken := service.TokenManager.Hash(res.Tokens.RefreshToken)
	_, err = db.Exec(`
		UPDATE sessions
		SET expires_at = NOW() - INTERVAL '1 hour'
		WHERE refresh_token = $1
	`, hashedToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_RevokedTokenReuse(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	hashedToken := service.TokenManager.Hash(res.Tokens.RefreshToken)
	// manually revoke
	_, err = db.Exec(`
		UPDATE sessions
		SET revoked_at = NOW(), revocation_reason = 'manual'
		WHERE refresh_token = $1
	`, hashedToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)

	// verify compromise escalation
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE compromised_at IS NOT NULL
	`).Scan(&count)
	require.NoError(t, err)
	require.GreaterOrEqual(t, count, 1)
}

func TestRefreshToken_AlreadyCompromised(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	hashedToken := service.TokenManager.Hash(res.Tokens.RefreshToken)
	_, err = db.Exec(`
		UPDATE sessions
		SET compromised_at = NOW()
		WHERE refresh_token = $1
	`, hashedToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_ConcurrentRace(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	errs := make(chan error, 2)

	refresh := func() {
		defer wg.Done()
		_, err := service.RefreshToken(ctx, res.Tokens.RefreshToken)
		errs <- err
	}

	go refresh()
	go refresh()
	wg.Wait()
	close(errs)

	var success, compromised int
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, auth.ErrInvalidCredentials) {
			compromised++
		}
	}

	require.Equal(t, 1, success)
	require.Equal(t, 1, compromised)
}

func TestRefreshToken_AfterPasswordChange(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, user.ID)

	res, err := service.Login(ctx, "test@example.com", "OldPassword123!")
	require.NoError(t, err)

	err = service.ChangePassword(ctx, "OldPassword123!", "NewPassword123!")
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_AfterLogout(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	err = service.Logout(ctx, res.Tokens.RefreshToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_LogoutThenReplay(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	refreshed, err := service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.NoError(t, err)

	err = service.Logout(ctx, refreshed.RefreshToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, refreshed.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_MultiDeviceIsolation(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx1 := testutil.CtxWithRequestMeta(ctx)
	ctx2 := testutil.CtxWithRequestMeta(ctx)

	_, err := service.RegisterUser(ctx1, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	device1, err := service.Login(ctx1, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	device2, err := service.Login(ctx2, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	// compromise device 1
	err = service.Logout(ctx1, device1.Tokens.RefreshToken)
	require.NoError(t, err)

	// device 2 should still work
	_, err = service.RefreshToken(ctx2, device2.Tokens.RefreshToken)
	require.NoError(t, err)
}

func TestRefreshToken_DeletedUser(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	res, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE users
		SET deleted_at = NOW()
		WHERE id = $1
	`, user.ID)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, res.Tokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, auth.ErrInvalidCredentials, err)
}

func TestRefreshToken_Disabled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	flagsService := flags.New(flags.Config{
		RefreshTokensEnabled: false,
	})

	svc := &auth.Service{
		Flags: flagsService,
	}

	_, err := svc.RefreshToken(ctx, "some-refresh-token")

	require.Error(t, err)

	require.ErrorIs(t, err, auth.ErrRefreshDisabled)
}
