//go:build integration

package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

var c noopCrypto

func seedUserWithUnconfirmedTOTP(
	t *testing.T,
	db *sql.DB,
	userID uuid.UUID,
	encryptedSecret []byte,
) uuid.UUID {
	methodID := uuid.New()

	_, err := db.Exec(`
		INSERT INTO user_mfa_methods (
			id,
			user_id,
			type,
			secret_ciphertext,
			created_at
		) VALUES ($1, $2, $3, $4, now())
	`,
		methodID,
		userID,
		domain.MFAMethodTOTP,
		encryptedSecret,
	)
	require.NoError(t, err)

	return methodID
}

func TestConfirmMFAMethod_Success(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	userID := uuid.New()
	ctx = testutil.CtxWithUserID(ctx, uuid.New())

	email := "user@email.com"
	ctx = testutil.CtxWithEmail(ctx, email)

	seedUser(t, db, userID, email, ctx)

	// generate real TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestApp",
		AccountName: "user@test.com",
	})
	require.NoError(t, err)

	encryptedSecret, _ := c.Encrypt([]byte(key.Secret()))

	methodID := seedUserWithUnconfirmedTOTP(t, db, userID, encryptedSecret)

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	_, err = service.ConfirmMFAMethod(ctx, methodID, code)
	require.NoError(t, err)

	var confirmedAt *time.Time
	err = db.QueryRow(`
		SELECT confirmed_at
		FROM user_mfa_methods
		WHERE id = $1
	`, methodID).Scan(&confirmedAt)
	require.NoError(t, err)
	require.NotNil(t, confirmedAt)
}

func TestConfirmMFAMethod_NotFound(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	_, err := service.ConfirmMFAMethod(ctx, uuid.New(), "123456")
	require.Error(t, err)
}

func TestConfirmMFAMethod_AlreadyConfirmed(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	userID := uuid.New()
	ctx = testutil.CtxWithUserID(ctx, uuid.New())

	email := "user@email.com"
	ctx = testutil.CtxWithEmail(ctx, email)

	seedUser(t, db, userID, email, ctx)

	methodID := uuid.New()

	_, err := db.Exec(`
		INSERT INTO user_mfa_methods (
			id,
			user_id,
			type,
			secret_ciphertext,
			confirmed_at,
			created_at
		) VALUES ($1, $2, $3, $4, now(), now())
	`,
		methodID,
		userID,
		domain.MFAMethodTOTP,
		[]byte("irrelevant"),
	)
	require.NoError(t, err)

	_, err = service.ConfirmMFAMethod(ctx, methodID, "123456")
	require.Error(t, err)

	require.ErrorIs(t, err, auth.ErrMethodAlreadyConfirmed)
}

func TestConfirmMFAMethod_InvalidCode(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	userID := uuid.New()
	ctx = testutil.CtxWithUserID(ctx, uuid.New())

	email := "user@email.com"
	ctx = testutil.CtxWithEmail(ctx, email)

	seedUser(t, db, userID, email, ctx)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestApp",
		AccountName: "user@test.com",
	})
	require.NoError(t, err)

	encryptedSecret, err := c.Encrypt([]byte(key.Secret()))
	require.NoError(t, err)

	methodID := seedUserWithUnconfirmedTOTP(t, db, userID, encryptedSecret)

	_, err = service.ConfirmMFAMethod(ctx, methodID, "000000")
	require.Error(t, err)

	require.ErrorIs(t, err, auth.ErrInvalidMFACode)
}

func TestConfirmMFAMethod_ExpiredMethod(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	userID := uuid.New()
	ctx = testutil.CtxWithUserID(ctx, uuid.New())

	email := "user@email.com"
	ctx = testutil.CtxWithEmail(ctx, email)

	seedUser(t, db, userID, email, ctx)

	// generate real TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestApp",
		AccountName: "user@test.com",
	})
	require.NoError(t, err)

	encryptedSecret, _ := c.Encrypt([]byte(key.Secret()))

	methodID := seedUserWithUnconfirmedTOTP(t, db, userID, encryptedSecret)

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	_, err = db.Exec(`
		UPDATE user_mfa_methods
		SET expires_at = now()
		WHERE id = $1
		`, methodID)
	require.NoError(t, err)

	_, err = service.ConfirmMFAMethod(ctx, methodID, code)
	require.Error(t, err)

	require.ErrorIs(t, err, auth.ErrMFAMethodExpired)
}
