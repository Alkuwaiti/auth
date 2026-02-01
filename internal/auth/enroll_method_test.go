//go:build integration

package auth

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
)

func TestEnrollMethod(t *testing.T) {
	tests := []struct {
		name               string
		method             mfa.MFAMethodType
		hasActiveMFAMethod bool
		wantErr            bool
		wantURI            bool
	}{
		{
			name:    "invalid method type",
			method:  mfa.MFAMethodType("invalid"),
			wantErr: true,
		},
		{
			name:    "method already exists",
			method:  mfa.MFAMethodTOTP,
			wantErr: true,
		},
		{
			name:    "encryption failure",
			method:  mfa.MFAMethodTOTP,
			wantErr: true,
		},
		{
			name:    "successful enrollment",
			method:  mfa.MFAMethodTOTP,
			wantURI: true,
		},
	}

	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()
	ctx = testutil.CtxWithUserID(ctx, uuid.New())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}
