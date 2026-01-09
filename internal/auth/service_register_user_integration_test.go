//go:build integration

package auth

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/user"
	"github.com/stretchr/testify/require"
)

func TestRegisterUser_Success(t *testing.T) {
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

	userService := user.NewTestUserService(db)

	user, err := userService.GetUserByEmail(ctx, input.Email)

	require.NoError(t, err)
	require.Equal(t, input.Email, user.Email)
	require.NotEmpty(t, user.PasswordHash)
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
	require.ErrorIs(t, err, &apperrors.InvalidCredentialsError{})
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
	require.ErrorIs(t, err, &apperrors.InvalidCredentialsError{})
}

func TestRegisterUser_Success_AuditTrail(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	auditService := audit.NewTestAuditService(db)

	auditLog, err := auditService.GetAuditLogByUserID(ctx, user.ID)
	require.NoError(t, err)

	require.Equal(t, string(audit.ActionCreateUser), auditLog.Action)
	require.Equal(t, user.ID, auditLog.UserID)
	require.NotEmpty(t, auditLog.CreatedAt)

}

func TestRegisterUser_Success_ValidatePassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "workingPassword123!!",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must be at least 8 characters", ve.Msg)
}

func TestRegisterUser_Fail_ValidatePasswordShortPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "pass",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must be at least 8 characters", ve.Msg)
}

func TestRegisterUser_Fail_ValidatePasswordLongPassword(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "thisisaverylongpassword,letscontinueontillwehitthemaximumnumberofcharsavailableforushere.iamrunningoutofthingstosay,anditisgettingveryweirdsoireallyhopeigottoitbythislikewowokherewegoijustneedsomereallydumbcharactersforthistogettowhereineedittouhfjrtguvrybvpncqmyxemtchrgycnesrotcyuncyrbvngcp",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "maximum 255 characters", ve.Msg)
}
func TestRegisterUser_Fail_ValidatePasswordNoUpperCase(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "nouppercaseletters",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one uppercase letter", ve.Msg)
}

func TestRegisterUser_Fail_ValidatePasswordNoLowerCase(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "NOLOWERCASELETTERS",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one lowercase letter", ve.Msg)
}

func TestRegisterUser_Fail_ValidatePasswordNoNumbers(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "passwordWithNoNumbers",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one number", ve.Msg)
}

func TestRegisterUser_Fail_ValidatePasswordNoSpecialCharacters(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	// register user once
	_, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "passwordWithNoSpecialChars1",
	})

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one special character", ve.Msg)
}
