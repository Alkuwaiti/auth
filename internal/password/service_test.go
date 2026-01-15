package password

import (
	"testing"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectedMsg string
		shouldPass  bool
	}{
		{
			name:       "Success",
			password:   "ValidPassword123!",
			shouldPass: true,
		},
		{
			name:        "ShortPassword",
			password:    "pass",
			expectedMsg: "must be at least 8 characters",
			shouldPass:  false,
		},
		{
			name:        "LongPassword",
			password:    "thisisaverylongpassword,letscontinueontillwehitthemaximumnumberofcharsavailableforushere.iamrunningoutofthingstosay,anditisgettingveryweirdsoireallyhopeigottoitbythislikewowokherewegoijustneedsomereallydumbcharactersforthistogettowhereineedittouhfjrtguvrybvpncqmyxemtchrgycnesrotcyuncyrbvngcp",
			expectedMsg: "maximum 255 characters",
			shouldPass:  false,
		},
		{
			name:        "NoUpperCase",
			password:    "nouppercaseletters",
			expectedMsg: "must contain at least one uppercase letter",
			shouldPass:  false,
		},
		{
			name:        "NoLowerCase",
			password:    "NOLOWERCASELETTERS",
			expectedMsg: "must contain at least one lowercase letter",
			shouldPass:  false,
		},
		{
			name:        "NoNumbers",
			password:    "passwordWithNoNumbers",
			expectedMsg: "must contain at least one number",
			shouldPass:  false,
		},
		{
			name:        "NoSpecialCharacters",
			password:    "passwordWithNoSpecialChars1",
			expectedMsg: "must contain at least one special character",
			shouldPass:  false,
		},
	}

	service := NewService(12)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.Validate(tt.password)

			if tt.shouldPass {
				require.NoError(t, err)
			} else {
				var ve *apperrors.ValidationError
				require.ErrorAs(t, err, &ve)
				require.Equal(t, "password", ve.Field)
				require.Equal(t, tt.expectedMsg, ve.Msg)
			}
		})
	}
}
