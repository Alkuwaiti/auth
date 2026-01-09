package password

import (
	"testing"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/stretchr/testify/require"
)

func TestValidatePassword_Success(t *testing.T) {
	service := NewService(12)

	password := "workingPassword123!!"

	err := service.Validate(password)

	require.NoError(t, err)
}

func TestValidatePasswordShortPassword_Fail(t *testing.T) {
	service := NewService(12)

	password := "pass"

	err := service.Validate(password)

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must be at least 8 characters", ve.Msg)
}

func TestValidatePasswordLongPassword_Fail(t *testing.T) {
	service := NewService(12)

	password := "thisisaverylongpassword,letscontinueontillwehitthemaximumnumberofcharsavailableforushere.iamrunningoutofthingstosay,anditisgettingveryweirdsoireallyhopeigottoitbythislikewowokherewegoijustneedsomereallydumbcharactersforthistogettowhereineedittouhfjrtguvrybvpncqmyxemtchrgycnesrotcyuncyrbvngcp"

	err := service.Validate(password)

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "maximum 255 characters", ve.Msg)
}

func TestValidatePasswordNoUpperCase_Fail(t *testing.T) {
	service := NewService(12)

	password := "nouppercaseletters"

	err := service.Validate(password)

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one uppercase letter", ve.Msg)
}

func TestValidatePasswordNoLowerCase_Fail(t *testing.T) {
	service := NewService(12)

	password := "NOLOWERCASELETTERS"

	err := service.Validate(password)

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one lowercase letter", ve.Msg)
}

func TestValidatePasswordNoNumbers_Fail(t *testing.T) {
	service := NewService(12)

	password := "passwordWithNoNumbers"

	err := service.Validate(password)

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one number", ve.Msg)
}

func TestValidatePasswordNoSpecialCharacters_Fail(t *testing.T) {
	service := NewService(12)

	password := "passwordWithNoSpecialChars1"

	err := service.Validate(password)

	var ve *apperrors.ValidationError
	require.ErrorAs(t, err, &ve)

	require.Equal(t, "password", ve.Field)
	require.Equal(t, "must contain at least one special character", ve.Msg)
}
