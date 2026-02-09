package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

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

func (r *repo) beginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

func (r *repo) execTx(ctx context.Context, fn func(*postgres.Queries) error) error {
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

func (r *repo) createSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) (Session, error) {
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
		return Session{}, err
	}

	return toSessionModel(session), nil
}

func (r *repo) getSessionByRefreshToken(ctx context.Context, refreshToken string) (Session, error) {
	session, err := r.queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, err
	}

	return toSessionModel(session), err
}

func (r *repo) revokeSession(ctx context.Context, SessionID uuid.UUID, revocationReason RevocationReason) error {
	if err := r.queries.RevokeSession(ctx, postgres.RevokeSessionParams{
		ID: SessionID,
		RevocationReason: sql.NullString{
			String: string(revocationReason),
			Valid:  revocationReason != "",
		},
	}); err != nil {
		return err
	}

	return nil
}

func (r *repo) updatePasswordAndRevokeSessions(
	ctx context.Context,
	userID uuid.UUID,
	newPasswordHash string,
	reason RevocationReason,
) error {
	return r.execTx(ctx, func(q *postgres.Queries) error {
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

type RotateSessionInput struct {
	oldSessionID     uuid.UUID
	userID           uuid.UUID
	expiry           time.Time
	revocationReason RevocationReason
	refreshToken     string
	ipAddress        string
	userAgent        string
}

func (r *repo) rotateSession(
	ctx context.Context,
	input RotateSessionInput,
) error {
	return r.execTx(ctx, func(queries *postgres.Queries) error {
		if err := queries.RevokeSession(ctx, postgres.RevokeSessionParams{
			ID: input.oldSessionID,
			RevocationReason: sql.NullString{
				String: string(input.revocationReason),
				Valid:  input.revocationReason != "",
			},
		}); err != nil {
			return err
		}

		_, err := queries.CreateSession(ctx, postgres.CreateSessionParams{
			UserID:       input.userID,
			RefreshToken: input.refreshToken,
			UserAgent: sql.NullString{
				String: input.userAgent,
				Valid:  input.userAgent != "",
			},
			IpAddress: sql.NullString{
				String: input.ipAddress,
				Valid:  input.ipAddress != "",
			},
			ExpiresAt: input.expiry,
		})
		if err != nil {
			return err
		}

		return nil
	})
}

func (r *repo) revokeAndMarkSessionsCompromised(
	ctx context.Context,
	userID uuid.UUID,
	reason RevocationReason,
) error {
	return r.execTx(ctx, func(q *postgres.Queries) error {
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

func (r *repo) deleteUserAndRevokeSessions(
	ctx context.Context,
	userID uuid.UUID,
	deletionReason DeletionReason,
	revocationReason RevocationReason,
) error {
	return r.execTx(ctx, func(q *postgres.Queries) error {
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
			return ErrUserNotFoundOrAlreadyDeleted
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

func (r *repo) userExists(ctx context.Context, username, email string) (bool, error) {
	exists, err := r.queries.UserExists(ctx, postgres.UserExistsParams{
		Username: username,
		Email:    email,
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *repo) getUserByEmail(ctx context.Context, email string) (User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return toUserModelFromEmailRow(user), nil
}

func (r *repo) getUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	user, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return toUserModelFromIDRow(user), nil
}

func (r *repo) createUser(
	ctx context.Context,
	username, email, passwordHash string,
) (User, error) {

	userID, err := uuid.NewV7()
	if err != nil {
		return User{}, err
	}

	var (
		user   User
		dbUser postgres.User
		roleID uuid.UUID
	)

	err = r.execTx(ctx, func(q *postgres.Queries) error {
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
		return User{}, err
	}

	return user, nil
}

func toSessionModel(session postgres.Session) Session {
	var revokedAt *time.Time
	if session.RevokedAt.Valid {
		revokedAt = &session.RevokedAt.Time
	}

	var compromisedAt *time.Time
	if session.CompromisedAt.Valid {
		compromisedAt = &session.CompromisedAt.Time
	}

	return Session{
		ID:               session.ID,
		UserID:           session.UserID,
		RefreshToken:     session.RefreshToken,
		UserAgent:        session.UserAgent.String,
		IPAddress:        session.IpAddress.String,
		CreatedAt:        session.CreatedAt.Time,
		ExpiresAt:        session.ExpiresAt,
		RevokedAt:        revokedAt,
		RevocationReason: RevocationReason(session.RevocationReason.String),
		CompromisedAt:    compromisedAt,
	}
}

func toUserModel(user postgres.User) User {
	var deletedAt *time.Time
	if user.DeletedAt.Valid {
		deletedAt = &user.DeletedAt.Time
	}

	var deletionReason *DeletionReason
	if user.DeletionReason.Valid {
		dr := DeletionReason(user.DeletionReason.String)
		deletionReason = &dr
	}

	return User{
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

func toUserModelFromEmailRow(row postgres.GetUserByEmailRow) User {
	var deletedAt *time.Time
	if row.DeletedAt.Valid {
		deletedAt = &row.DeletedAt.Time
	}

	var deletionReason *DeletionReason
	if row.DeletionReason.Valid {
		dr := DeletionReason(row.DeletionReason.String)
		deletionReason = &dr
	}

	return User{
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

func toUserModelFromIDRow(row postgres.GetUserByIDRow) User {
	var deletedAt *time.Time
	if row.DeletedAt.Valid {
		deletedAt = &row.DeletedAt.Time
	}

	var deletionReason *DeletionReason
	if row.DeletionReason.Valid {
		dr := DeletionReason(row.DeletionReason.String)
		deletionReason = &dr
	}

	return User{
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
