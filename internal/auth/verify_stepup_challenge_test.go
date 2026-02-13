//go:build integration

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestVerifyStepUpChallenge_Success(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, secret := setupUserWithTOTP(t, svc, ctx)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")

	resp, err := svc.VerifyStepUpChallenge(ctx, challengeID, code)
	require.NoError(t, err)

	require.NotEmpty(t, resp.StepUpToken)
	require.Greater(t, resp.ExpiresIn, 0)

	dbChallenge, err := svc.repoI.GetChallengeByID(ctx, challengeID)
	require.NoError(t, err)
	require.NotNil(t, dbChallenge.ConsumedAt)
}

func TestVerifyStepUpChallenge_InvalidCode(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)
	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")

	_, err := svc.VerifyStepUpChallenge(ctx, challengeID, "000000")
	require.Error(t, err)

	require.IsType(t, &apperrors.InvalidMFACodeError{}, err)

	// Ensure challenge NOT consumed
	dbChallenge, err := svc.repoI.GetChallengeByID(ctx, challengeID)
	require.NoError(t, err)
	require.Nil(t, dbChallenge.ConsumedAt)
}

func TestVerifyStepUpChallenge_Forbidden_UserMismatch(t *testing.T) {
	ctx := context.Background()
	svc, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	_, challengeID, _ := setupUserWithTOTP(t, svc, ctx)

	otherUserID := uuid.New()

	ctx = testutil.CtxWithUserID(ctx, otherUserID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")

	_, err := svc.VerifyStepUpChallenge(ctx, challengeID, "000000")
	require.Error(t, err)

	require.IsType(t, &apperrors.ForbiddenError{}, err)
}

func TestVerifyStepUpChallenge_Expired(t *testing.T) {
	ctx := context.Background()
	svc, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)

	// Expire the challenge
	_, err := db.ExecContext(ctx, `
		UPDATE mfa_challenges
		SET expires_at = $2
		WHERE id = $1
	`, challengeID, time.Now().Add(-1*time.Minute))
	require.NoError(t, err)

	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")

	_, err = svc.VerifyStepUpChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.IsType(t, &apperrors.BadRequestError{}, err)
}

// TODO: figure out why this is failing
// func TestVerifyStepUpChallenge_AlreadyConsumed(t *testing.T) {
// 	ctx := context.Background()
// 	svc, db, cleanup := setupTestAuthService(t)
// 	defer cleanup()
//
// 	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)
//
// 	_, err := db.ExecContext(ctx, `
// 		UPDATE mfa_challenges
// 		SET consumed_at = NOW()
// 		WHERE id = $1
// 	`, challengeID)
// 	require.NoError(t, err)
//
// 	ctx = testutil.CtxWithUserID(ctx, userID)
// 	ctx = testutil.CtxWithEmail(ctx, "email@email.com")
//
// 	_, err = svc.VerifyStepUpChallenge(ctx, challengeID, "000000")
// 	require.Error(t, err)
//
// 	require.IsType(t, &apperrors.BadRequestError{}, err)
// }
