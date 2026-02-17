package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lib/pq"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, err
	}

	return toUserModelFromEmailRow(user), nil
}

func (r *repo) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	user, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, err
	}

	return toUserModelFromIDRow(user), nil
}

func (r *repo) CreateUser(ctx context.Context, username, email, passwordHash string) (domain.User, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return domain.User{}, err
	}

	var (
		user   domain.User
		dbUser postgres.User
		roleID uuid.UUID
	)

	err = r.ExecTx(ctx, func(q *postgres.Queries) error {
		dbUser, err = q.CreateUser(ctx, postgres.CreateUserParams{
			ID:           userID,
			Username:     username,
			Email:        email,
			PasswordHash: passwordHash,
		})
		if err != nil {
			var pgErr *pq.Error
			if errors.As(err, &pgErr) {
				if pgErr.Code == "23505" { // Unique constraint error code
					return ErrRecordAlreadyExists
				}
			}
			return err
		}

		roleID, err = q.GetRoleIDByName(ctx, "user")
		if err != nil {
			return err
		}

		err = q.AssignRoleToUser(ctx, postgres.AssignRoleToUserParams{
			UserID: userID,
			RoleID: roleID,
		})
		if err != nil {
			return err
		}

		user = toUserModel(dbUser)
		return nil
	})

	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}

func toUserModel(user postgres.User) domain.User {
	var deletedAt *time.Time
	if user.DeletedAt.Valid {
		deletedAt = &user.DeletedAt.Time
	}

	var deletionReason *domain.DeletionReason
	if user.DeletionReason.Valid {
		dr := domain.DeletionReason(user.DeletionReason.String)
		deletionReason = &dr
	}

	return domain.User{
		ID:              user.ID,
		Email:           user.Email,
		Username:        user.Username,
		PasswordHash:    user.PasswordHash,
		IsEmailVerified: user.IsEmailVerified,
		IsActive:        user.IsActive,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
		DeletedAt:       deletedAt,
		DeletionReason:  deletionReason,
		MFAEnabled:      user.MfaEnabled,
	}
}

func toUserModelFromEmailRow(row postgres.GetUserByEmailRow) domain.User {
	var deletedAt *time.Time
	if row.DeletedAt.Valid {
		deletedAt = &row.DeletedAt.Time
	}

	var deletionReason *domain.DeletionReason
	if row.DeletionReason.Valid {
		dr := domain.DeletionReason(row.DeletionReason.String)
		deletionReason = &dr
	}

	return domain.User{
		ID:              row.ID,
		Email:           row.Email,
		Username:        row.Username,
		PasswordHash:    row.PasswordHash,
		IsEmailVerified: row.IsEmailVerified,
		IsActive:        row.IsActive,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
		DeletedAt:       deletedAt,
		DeletionReason:  deletionReason,
		Roles:           row.Roles,
		MFAEnabled:      row.MfaEnabled,
	}
}

func toUserModelFromIDRow(row postgres.GetUserByIDRow) domain.User {
	var deletedAt *time.Time
	if row.DeletedAt.Valid {
		deletedAt = &row.DeletedAt.Time
	}

	var deletionReason *domain.DeletionReason
	if row.DeletionReason.Valid {
		dr := domain.DeletionReason(row.DeletionReason.String)
		deletionReason = &dr
	}

	return domain.User{
		ID:              row.ID,
		Email:           row.Email,
		Username:        row.Username,
		PasswordHash:    row.PasswordHash,
		IsEmailVerified: row.IsEmailVerified,
		IsActive:        row.IsActive,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
		DeletedAt:       deletedAt,
		DeletionReason:  deletionReason,
		Roles:           row.Roles,
		MFAEnabled:      row.MfaEnabled,
	}
}
