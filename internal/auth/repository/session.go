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
