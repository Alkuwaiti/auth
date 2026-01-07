package auth

import (
	"context"
	"testing"

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
