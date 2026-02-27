//go:build integration

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRegisterUser(t *testing.T) {
	tests := []struct {
		name          string
		input         auth.RegisterUserInput
		setupExisting *auth.RegisterUserInput
		expectError   bool
		expectedError error
		checkDB       bool
	}{
		{
			name: "Success",
			input: auth.RegisterUserInput{
				Email:    "test@example.com",
				Password: "StrongPassword123!",
			},
			expectError: false,
			checkDB:     true,
		},
		{
			name: "DuplicateEmail",
			input: auth.RegisterUserInput{
				Email:    "test@example.com",
				Password: "StrongPassword123!",
			},
			setupExisting: &auth.RegisterUserInput{
				Email:    "test@example.com",
				Password: "StrongPassword123!",
			},
			expectError:   true,
			expectedError: auth.ErrUserExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, db, cleanup := setupTestAuthService(t)
			defer cleanup()

			ctx := context.Background()

			if tt.setupExisting != nil {
				_, err := service.RegisterUser(ctx, *tt.setupExisting)
				require.NoError(t, err)
			}

			_, err := service.RegisterUser(ctx, tt.input)

			if tt.expectError {
				require.Error(t, err)
				require.IsType(t, tt.expectedError, err)
			} else {
				require.NoError(t, err)

				if tt.checkDB {
					var (
						email        string
						passwordHash string
						isActive     bool
					)
					err = db.QueryRow(`
						SELECT email, password_hash, is_active
						FROM users
						WHERE email = $1
					`, tt.input.Email).Scan(&email, &passwordHash, &isActive)
					require.NoError(t, err)
					require.Equal(t, tt.input.Email, email)
					require.NotEmpty(t, passwordHash)
					require.True(t, isActive)
				}
			}
		})
	}
}

func TestRegisterUser_AuditTrail(t *testing.T) {
	service, db, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := context.Background()

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	})
	require.NoError(t, err)

	var auditLog struct {
		Action    string
		UserID    uuid.UUID
		CreatedAt time.Time
	}
	err = db.QueryRow(`
		SELECT action, user_id, created_at
		FROM audit_logs
		WHERE action = $1 AND user_id = $2
	`, audit.ActionCreateUser, user.ID).
		Scan(&auditLog.Action, &auditLog.UserID, &auditLog.CreatedAt)
	require.NoError(t, err)
	require.Equal(t, string(audit.ActionCreateUser), auditLog.Action)
	require.Equal(t, user.ID, auditLog.UserID)
	require.False(t, auditLog.CreatedAt.IsZero())
}
