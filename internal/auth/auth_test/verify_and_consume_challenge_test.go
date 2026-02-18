//go:build integration

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
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

	challenge, err := svc.VerifyAndConsumeChallenge(ctx, challengeID, code)
	require.NoError(t, err)
	require.Equal(t, challengeID, challenge.ChallengeID)

	dbChallenge, err := svc.Repo.GetChallengeByID(ctx, challengeID)
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

	_, err := svc.VerifyAndConsumeChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidMFACode)

	dbChallenge, err := svc.Repo.GetChallengeByID(ctx, challengeID)
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

	_, err = svc.VerifyAndConsumeChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidMFACode)
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

	_, err = svc.VerifyAndConsumeChallenge(ctx, challengeID, "000000")
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrInvalidMFACode)
}

func TestVerifyAndConsumeChallenge_SuccessWithBackupCode(t *testing.T) {
	ctx := context.Background()
	svc, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	userID, challengeID, _ := setupUserWithTOTP(t, svc, ctx)

	rawBackupCode := "ABCD-1234"

	hashedCode := svc.Hasher.Hash(rawBackupCode)

	var backupCodeID uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO mfa_backup_codes (user_id, code_hash)
		VALUES ($1, $2)
		RETURNING id
	`, userID, hashedCode).Scan(&backupCodeID)
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, "email@email.com")
	ctx = testutil.CtxWithRequestMeta(ctx)

	challenge, err := svc.VerifyAndConsumeChallenge(ctx, challengeID, rawBackupCode)

	require.NoError(t, err)
	require.Equal(t, challengeID, challenge.ChallengeID)

	var challengeConsumedAt *time.Time
	err = db.QueryRowContext(ctx, "SELECT consumed_at FROM mfa_challenges WHERE id = $1", challengeID).Scan(&challengeConsumedAt)
	require.NoError(t, err)
	require.NotNil(t, challengeConsumedAt)

	var codeConsumed time.Time
	err = db.QueryRowContext(ctx, "SELECT consumed_at FROM mfa_backup_codes WHERE id = $1", backupCodeID).Scan(&codeConsumed)
	require.NoError(t, err)
	require.NotNil(t, codeConsumed, "The specific backup code used should be marked as consumed")
}
