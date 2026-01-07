package auth

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestRegisterUser_Success(t *testing.T) {
	service, db, cleanup := testutil.SetupTestService(t)
	defer cleanup()

	ctx := context.Background()
	input := auth.RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "StrongPassword123!",
	}

	_, err := service.RegisterUser(ctx, input)
	require.NoError(t, err)

	userService := testutil.NewTestUserService(db)

	user, err := userService.GetUserByEmail(ctx, input.Email)

	require.NoError(t, err)
	require.Equal(t, input.Email, user.Email)
	require.NotEmpty(t, user.PasswordHash)
}
