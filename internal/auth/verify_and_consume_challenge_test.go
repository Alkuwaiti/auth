//go:build integration

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestVerifyAndConsumeChallenge_SuccessTOTP(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, secret := setupUserWithTOTP(t, svc, ctx)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")
	ctx = testutil.CtxWithRequestMeta(ctx)

	challenge, err := svc.verifyAndConsumeChallenge(ctx, challengeID, code)
	require.NoError(t, err)
	require.Equal(t, challengeID, challenge.ChallengeID)

	dbChallenge, err := svc.repo.GetChallengeByID(ctx, challengeID)
	require.NoError(t, err)
	require.NotNil(t, dbChallenge.ConsumedAt)
}

func TestVerifyAndConsumeChallenge_InvalidTOTP(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)

	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := svc.verifyAndConsumeChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidMFACodeError{}, err)

	dbChallenge, err := svc.repo.GetChallengeByID(ctx, challengeID)
	require.NoError(t, err)
	require.Equal(t, 1, dbChallenge.Attempts)
	require.Nil(t, dbChallenge.ConsumedAt)
}

func TestVerifyAndConsumeChallenge_MaxAttemptsExceeded(t *testing.T) {
	ctx := context.Background()
	svc, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)

	_, err := db.ExecContext(ctx, `
		UPDATE mfa_challenges
		SET attempts = $2
		WHERE id = $1
	`, challengeID, svc.Config.MaxChallengeAttempts)
	require.NoError(t, err)

	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err = svc.verifyAndConsumeChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidMFACodeError{}, err)
}

func TestVerifyAndConsumeChallenge_AlreadyConsumed(t *testing.T) {
	ctx := context.Background()
	svc, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)

	_, err := db.ExecContext(ctx, `
		UPDATE mfa_challenges
		SET consumed_at = NOW()
		WHERE id = $1
	`, challengeID)
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err = svc.verifyAndConsumeChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.IsType(t, &apperrors.InvalidMFACodeError{}, err)
}
