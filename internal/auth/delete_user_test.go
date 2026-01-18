//go:build integration

package auth

import (
	"testing"

	"github.com/alkuwaiti/auth/internal/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDeleteUser_Success(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	actor, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "actorUser",
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)

	err = service.DeleteUser(ctx, DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: DeletionReason("USER_IS_BOT"),
		ActorID:        actor.ID,
		Note:           "Some note",
	})

	require.NoError(t, err)
}

func TestDeleteUser_AlreadyDeleted(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	actor, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "actorUser",
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "testUser",
		Email:    "test@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	err = service.DeleteUser(ctx, DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: DeletionReason("USER_REQUEST"),
		ActorID:        actor.ID,
	})
	require.NoError(t, err)

	// second delete
	err = service.DeleteUser(ctx, DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: DeletionReason("USER_REQUEST"),
		ActorID:        actor.ID,
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "User not found or already deleted")
}

func TestDeleteUser_UserDoesNotExist(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	actor, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "actorUser",
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	err = service.DeleteUser(ctx, DeleteUserInput{
		UserID:         uuid.New(),
		DeletionReason: DeletionReason("ADMIN_ACTION"),
		ActorID:        actor.ID,
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "User not found or already deleted")
}

func TestDeleteUser_InvalidInput(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()

	err := service.DeleteUser(ctx, DeleteUserInput{
		UserID: uuid.Nil, // invalid
	})

	require.Error(t, err)
}

func TestDeleteUser_UserIsSoftDeleted(t *testing.T) {
	service, _, cleanup := setupTestAuthService(t)
	defer cleanup()

	ctx := testutil.CtxWithRequestMeta()
	ctx = testutil.CtxWithRoles(ctx, []string{"admin"})

	user, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "softDeleteUser",
		Email:    "soft@delete.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	actor, err := service.RegisterUser(ctx, RegisterUserInput{
		Username: "actorUser",
		Email:    "actor@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	err = service.DeleteUser(ctx, DeleteUserInput{
		UserID:         user.ID,
		DeletionReason: DeletionReason("USER_REQUEST"),
		ActorID:        actor.ID,
	})
	require.NoError(t, err)

	deletedUser, err := service.repo.getUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, deletedUser.DeletedAt)
	require.Equal(t, DeletionUserRequest, *deletedUser.DeletionReason)
}
