//go:build integration

package auth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEnrollMFAMethod(t *testing.T) {
	tests := []struct {
		name    string
		method  domain.MFAMethodType
		seed    func(t *testing.T, svc *auth.Service, db *sql.DB, userID uuid.UUID, ctx context.Context)
		wantErr bool
		wantURI bool
	}{
		{
			name:    "invalid method type",
			method:  domain.MFAMethodType("invalid"),
			wantErr: true,
		},
		{
			name:   "method already exists",
			method: domain.MFAMethodTOTP,
			seed: func(t *testing.T, svc *auth.Service, db *sql.DB, userID uuid.UUID, ctx context.Context) {

				_, err := db.ExecContext(ctx, `
						INSERT INTO user_mfa_methods (
							id,
							user_id,
							type,
							secret_ciphertext,
							confirmed_at,
							created_at
						) VALUES ($1, $2, $3, $4, now(), now())
					`,
					uuid.New(),
					userID,
					domain.MFAMethodTOTP,
					[]byte("encrypted-secret"),
				)
				require.NoError(t, err)
			},
			wantErr: true,
		},
		{
			name:    "successful enrollment",
			method:  domain.MFAMethodTOTP,
			wantURI: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, db, cleanup := setupTestAuthService(t)
			defer cleanup()

			ctx := context.Background()

			userID := uuid.New()

			email := "email.com"

			seedUser(t, db, userID, email, ctx)

			if tt.seed != nil {
				tt.seed(t, service, db, userID, ctx)
			}

			ctx = testutil.CtxWithUserID(ctx, userID)
			ctx = testutil.CtxWithEmail(ctx, email)

			res, err := service.EnrollMFAMethod(ctx, tt.method)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantURI {
				require.NotEmpty(t, res.SetupURI)
				require.Equal(t, tt.method, res.Method.Type)
			}
		})
	}
}
