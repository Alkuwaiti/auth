package password

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectedMsg string
		expectedErr error
	}{
		{
			name:        "Success",
			password:    "ValidPassword123!",
			expectedErr: nil,
		},
		{
			name:        "ShortPassword",
			password:    "pass",
			expectedMsg: "must be at least 8 characters",
			expectedErr: ErrPasswordTooShort,
		},
		{
			name:        "LongPassword",
			password:    "thisisaverylongpassword,letscontinueontillwehitthemaximumnumberofcharsavailableforushere.iamrunningoutofthingstosay,anditisgettingveryweirdsoireallyhopeigottoitbythislikewowokherewegoijustneedsomereallydumbcharactersforthistogettowhereineedittouhfjrtguvrybvpncqmyxemtchrgycnesrotcyuncyrbvngcp",
			expectedMsg: "maximum 255 characters",
			expectedErr: ErrPasswordTooLong,
		},
		{
			name:        "NoUpperCase",
			password:    "nouppercaseletters",
			expectedMsg: "must contain at least one uppercase letter",
			expectedErr: ErrPasswordMissingUppercase,
		},
		{
			name:        "NoLowerCase",
			password:    "NOLOWERCASELETTERS",
			expectedMsg: "must contain at least one lowercase letter",
			expectedErr: ErrPasswordMissingLowercase,
		},
		{
			name:        "NoNumbers",
			password:    "passwordWithNoNumbers",
			expectedMsg: "must contain at least one number",
			expectedErr: ErrPasswordMissingNumber,
		},
		{
			name:        "NoSpecialCharacters",
			password:    "passwordWithNoSpecialChars1",
			expectedMsg: "must contain at least one special character",
			expectedErr: ErrPasswordMissingSpecial,
		},
	}

	service := NewService(12)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.Validate(tt.password)

			if tt.expectedErr != nil {
				require.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
