//go:build integration

package auth_test

import (
	"context"
	"testing"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDeleteUser_Success(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	actor, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, actor.ID)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: domain.DeletionReason("USER_IS_BOT"),
		Note:           "Some note",
	})

	require.NoError(t, err)
}

func TestDeleteUser_AlreadyDeleted(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	actor, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, actor.ID)

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "test@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	err = service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: domain.DeletionReason("USER_REQUEST"),
	})
	require.NoError(t, err)

	// second delete
	err = service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: domain.DeletionReason("USER_REQUEST"),
	})

	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrUserNotFound)
}

func TestDeleteUser_UserDoesNotExist(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	actor, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, actor.ID)

	err = service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         uuid.New(),
		DeletionReason: domain.DeletionReason("ADMIN_ACTION"),
	})

	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrUserNotFound)
}

func TestDeleteUser_InvalidInput(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)

	err := service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID: uuid.Nil, // invalid
	})

	require.Error(t, err)
}

func TestDeleteUser_UserIsSoftDeleted(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()
	ctx := context.Background()
	ctx = testutil.CtxWithRequestMeta(ctx)
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	user, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "soft@delete.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	actor, err := service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	ctx = testutil.CtxWithUserID(ctx, actor.ID)

	err = service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: domain.DeletionReason("USER_REQUEST"),
	})
	require.NoError(t, err)

	deletedUser, err := service.Repo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, deletedUser.DeletedAt)
}
