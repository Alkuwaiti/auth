package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type repo struct {
	db      *sql.DB
	queries *postgres.Queries
}

func NewRepo(db *sql.DB) *repo {
	return &repo{
		db:      db,
		queries: postgres.New(db),
	}
}

func (r *repo) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

func (r *repo) ExecTx(ctx context.Context, fn func(*postgres.Queries) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	qtx := r.queries.WithTx(tx)

	if err := fn(qtx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (r *repo) CreateSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) (domain.Session, error) {
	session, err := r.queries.CreateSession(ctx, postgres.CreateSessionParams{
		UserID:       userID,
		RefreshToken: refreshToken,
		UserAgent: sql.NullString{
			String: userAgent,
			Valid:  userAgent != "",
		},
		IpAddress: sql.NullString{
			String: IPAddress,
			Valid:  IPAddress != "",
		},
		ExpiresAt: expiry,
	})
	if err != nil {
		return domain.Session{}, err
	}

	return toSessionModel(session), nil
}

func (r *repo) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (domain.Session, error) {
	session, err := r.queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Session{}, ErrNotFound
		}
		return domain.Session{}, err
	}

	return toSessionModel(session), err
}

func (r *repo) RevokeSession(ctx context.Context, SessionID uuid.UUID, revocationReason domain.RevocationReason) error {
	return r.queries.RevokeSession(ctx, postgres.RevokeSessionParams{
		ID: SessionID,
		RevocationReason: sql.NullString{
			String: string(revocationReason),
			Valid:  revocationReason != "",
		},
	})
}

func (r *repo) UpdatePasswordAndRevokeSessions(ctx context.Context, userID uuid.UUID, newPasswordHash string, reason domain.RevocationReason) error {
	return r.ExecTx(ctx, func(q *postgres.Queries) error {
		if err := q.UpdatePassword(ctx, postgres.UpdatePasswordParams{
			ID:           userID,
			PasswordHash: newPasswordHash,
		}); err != nil {
			return err
		}

		if err := q.RevokeAllUserSessions(ctx, postgres.RevokeAllUserSessionsParams{
			UserID: userID,
			RevocationReason: sql.NullString{
				String: string(reason),
				Valid:  reason != "",
			},
		}); err != nil {
			return err
		}

		return nil
	})
}

func (r *repo) RotateSession(ctx context.Context, input domain.RotateSessionInput) error {
	return r.ExecTx(ctx, func(queries *postgres.Queries) error {
		if err := queries.RevokeSession(ctx, postgres.RevokeSessionParams{
			ID: input.OldSessionID,
			RevocationReason: sql.NullString{
				String: string(input.RevocationReason),
				Valid:  input.RevocationReason != "",
			},
		}); err != nil {
			return err
		}

		_, err := queries.CreateSession(ctx, postgres.CreateSessionParams{
			UserID:       input.UserID,
			RefreshToken: input.RefreshToken,
			UserAgent: sql.NullString{
				String: input.UserAgent,
				Valid:  input.UserAgent != "",
			},
			IpAddress: sql.NullString{
				String: input.IPAddress,
				Valid:  input.IPAddress != "",
			},
			ExpiresAt: input.Expiry,
		})
		if err != nil {
			return err
		}

		return nil
	})
}

func (r *repo) RevokeAndMarkSessionsCompromised(ctx context.Context, userID uuid.UUID, reason domain.RevocationReason) error {
	return r.ExecTx(ctx, func(q *postgres.Queries) error {
		if err := q.RevokeAllUserSessions(ctx, postgres.RevokeAllUserSessionsParams{
			UserID: userID,
			RevocationReason: sql.NullString{
				String: string(reason),
				Valid:  reason != "",
			},
		}); err != nil {
			return err
		}

		if err := q.MarkSessionsCompromised(ctx, userID); err != nil {
			return err
		}

		return nil
	})
}

func (r *repo) DeleteUserAndRevokeSessions(ctx context.Context, userID uuid.UUID, deletionReason domain.DeletionReason, revocationReason domain.RevocationReason) error {
	return r.ExecTx(ctx, func(q *postgres.Queries) error {
		rows, err := q.DeleteUser(ctx, postgres.DeleteUserParams{
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
			return ErrNotFound
		}

		if err := q.RevokeAllUserSessions(ctx, postgres.RevokeAllUserSessionsParams{
			UserID: userID,
			RevocationReason: sql.NullString{
				String: string(revocationReason),
				Valid:  revocationReason != "",
			},
		}); err != nil {
			return err
		}

		return nil
	})
}

func (r *repo) UserExists(ctx context.Context, username, email string) (bool, error) {
	exists, err := r.queries.UserExists(ctx, postgres.UserExistsParams{
		Username: username,
		Email:    email,
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

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

func toSessionModel(session postgres.Session) domain.Session {
	var revokedAt *time.Time
	if session.RevokedAt.Valid {
		revokedAt = &session.RevokedAt.Time
	}

	var compromisedAt *time.Time
	if session.CompromisedAt.Valid {
		compromisedAt = &session.CompromisedAt.Time
	}

	return domain.Session{
		ID:               session.ID,
		UserID:           session.UserID,
		RefreshToken:     session.RefreshToken,
		UserAgent:        session.UserAgent.String,
		IPAddress:        session.IpAddress.String,
		CreatedAt:        session.CreatedAt.Time,
		ExpiresAt:        session.ExpiresAt,
		RevokedAt:        revokedAt,
		RevocationReason: domain.RevocationReason(session.RevocationReason.String),
		CompromisedAt:    compromisedAt,
	}
}

func (r *repo) InsertBackupCodes(ctx context.Context, tx *sql.Tx, userID uuid.UUID, hashedCodes []string) error {
	return r.queries.WithTx(tx).InsertBackupCodes(ctx, postgres.InsertBackupCodesParams{
		UserID:  userID,
		Column2: hashedCodes,
	})
}

func (r *repo) DeleteBackupCodesForUser(ctx context.Context, tx *sql.Tx, userID uuid.UUID) error {
	return r.queries.WithTx(tx).DeleteBackupCodesForUser(ctx, userID)
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
