package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func setupUserWithTOTP(t *testing.T, svc *service, ctx context.Context) (userID uuid.UUID, challengeID uuid.UUID, secret string) {
	t.Helper()

	// register user
	user, err := svc.RegisterUser(ctx, RegisterUserInput{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	userID = user.ID
	ctx = testutil.CtxWithUserID(ctx, userID)
	ctx = testutil.CtxWithEmail(ctx, user.Email)

	// enroll TOTP
	enrollment, err := svc.EnrollMFAMethod(
		ctx,
		MFAMethodTOTP,
	)
	require.NoError(t, err)

	// extract secret from otpauth URL
	key, err := otp.NewKeyFromURL(enrollment.SetupURI)
	require.NoError(t, err)
	secret = key.Secret()

	// confirm TOTP
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	_, err = svc.ConfirmMFAMethod(ctx, enrollment.Method.ID, code)
	require.NoError(t, err)

	// create MFA challenge
	challenge, err := svc.repo.createChallenge(ctx, MFAChallenge{
		MethodID:      enrollment.Method.ID,
		UserID:        user.ID,
		Scope:         string(ScopeLogin),
		ChallengeType: ChallengeLogin,
	})
	require.NoError(t, err)

	challengeID = challenge.ID

	return
}

func TestCompleteLoginMFA_Success(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	userID, challengeID, secret := setupUserWithTOTP(t, service, ctx)

	// generate valid code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	tokens, err := service.CompleteLoginMFA(ctx, challengeID, code)
	require.NoError(t, err)

	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	require.Equal(t, userID, tokens.UserID)
}

func TestCompleteLoginMFA_InvalidChallenge(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	_, challengeID, _ := setupUserWithTOTP(t, service, ctx)

	_, err := service.CompleteLoginMFA(ctx, challengeID, "123456")
	require.Error(t, err)

	require.Error(t, err)
}

func TestCompleteLoginMFA_UserDeleted(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	userID, challengeID, secret := setupUserWithTOTP(t, service, ctx)

	// delete user
	_, err := db.Exec(`
		UPDATE users
		SET deleted_at = NOW()
		WHERE id = $1
	`, userID)
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	tokens, err := service.CompleteLoginMFA(ctx, challengeID, code)
	require.NoError(t, err)
	require.NotEmpty(t, tokens.AccessToken)
}
