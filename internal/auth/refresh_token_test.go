//go:build integration

package auth

import (
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestRefreshToken_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	loginTokens, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	refreshed, err := service.RefreshToken(ctx, loginTokens.RefreshToken)
	require.NoError(t, err)

	require.NotEmpty(t, refreshed.AccessToken)
	require.NotEmpty(t, refreshed.RefreshToken)
	require.NotEqual(t, loginTokens.RefreshToken, refreshed.RefreshToken)
	require.Equal(t, loginTokens.UserID, refreshed.UserID)

	// old session revoked
	var revokedAt *time.Time
	err = db.QueryRow(`
		SELECT revoked_at
		FROM sessions
		WHERE refresh_token = $1
	`, loginTokens.RefreshToken).Scan(&revokedAt)
	require.NoError(t, err)
	require.NotNil(t, revokedAt)

	// new session exists
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM sessions
		WHERE refresh_token = $1
	`, refreshed.RefreshToken).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	_, err := service.RefreshToken(ctx, "non-existent-token")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestRefreshToken_ExpiredSession(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	loginTokens, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE sessions
		SET expires_at = NOW() - INTERVAL '1 hour'
		WHERE refresh_token = $1
	`, loginTokens.RefreshToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, loginTokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidCredentialsError{}, err)
}

func TestRefreshToken_RevokedTokenReuse(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	loginTokens, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	// manually revoke
	_, err = db.Exec(`
		UPDATE sessions
		SET revoked_at = NOW(), revocation_reason = 'manual'
		WHERE refresh_token = $1
	`, loginTokens.RefreshToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, loginTokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, &apperrors.SessionCompromisedError{}, err)

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

	ctx := testutil.CtxWithRequestMeta()

	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	loginTokens, err := service.Login(ctx, "test@example.com", "StrongPassword123!")
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE sessions
		SET compromised_at = NOW()
		WHERE refresh_token = $1
	`, loginTokens.RefreshToken)
	require.NoError(t, err)

	_, err = service.RefreshToken(ctx, loginTokens.RefreshToken)
	require.Error(t, err)
	require.IsType(t, &apperrors.SessionCompromisedError{}, err)
}
