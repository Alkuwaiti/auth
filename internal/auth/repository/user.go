package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, domain.ErrNotFound
		}
		return domain.User{}, err
	}

	return toUserModelFromEmailRow(user), nil
}

func (r *Repo) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	user, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, domain.ErrNotFound
		}
		return domain.User{}, err
	}

	return toUserModelFromIDRow(user), nil
}

func (r *Repo) CreateUser(ctx context.Context, email string, passwordHash *string) (domain.User, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return domain.User{}, err
	}

	var nullPassword sql.NullString
	if passwordHash != nil {
		nullPassword = sql.NullString{
			String: *passwordHash,
			Valid:  true,
		}
	} else {
		nullPassword = sql.NullString{
			Valid: false,
		}
	}

	user, err := r.queries.CreateUser(ctx, postgres.CreateUserParams{
		ID:           userID,
		Email:        email,
		PasswordHash: nullPassword,
	})
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique constraint error code
				return domain.User{}, domain.ErrRecordAlreadyExists
			}
		}
		return domain.User{}, err
	}

	return toUserModel(user), nil
}

func (r *Repo) DeleteUser(ctx context.Context, userID uuid.UUID, deletionReason domain.DeletionReason) error {
	rows, err := r.queries.DeleteUser(ctx, postgres.DeleteUserParams{
		ID: userID,
		DeletionReason: sql.NullString{
			String: string(deletionReason),
			Valid:  deletionReason != "",
		},
	})
	if err != nil {
		return err
	}

	if rows == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func toUserModel(user postgres.CreateUserRow) domain.User {
	var deletedAt *time.Time
	if user.DeletedAt.Valid {
		deletedAt = &user.DeletedAt.Time
	}

	var deletionReason *domain.DeletionReason
	if user.DeletionReason.Valid {
		dr := domain.DeletionReason(user.DeletionReason.String)
		deletionReason = &dr
	}

	var passwordHash *string
	if user.PasswordHash.Valid {
		passwordHash = &user.PasswordHash.String
	}

	return domain.User{
		ID:              user.ID,
		Email:           user.Email,
		PasswordHash:    passwordHash,
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

	var passwordHash *string
	if row.PasswordHash.Valid {
		passwordHash = &row.PasswordHash.String
	}

	return domain.User{
		ID:              row.ID,
		Email:           row.Email,
		PasswordHash:    passwordHash,
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

	var passwordHash *string
	if row.PasswordHash.Valid {
		passwordHash = &row.PasswordHash.String
	}

	return domain.User{
		ID:              row.ID,
		Email:           row.Email,
		PasswordHash:    passwordHash,
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
