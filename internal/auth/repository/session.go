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

func (r *Repo) CreateSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) (domain.Session, error) {
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

func (r *Repo) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (domain.Session, error) {
	session, err := r.queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Session{}, domain.ErrNotFound
		}
		return domain.Session{}, err
	}

	return toSessionModel(session), err
}

func (r *Repo) RevokeSession(ctx context.Context, SessionID uuid.UUID, revocationReason domain.RevocationReason) error {
	return r.queries.RevokeSession(ctx, postgres.RevokeSessionParams{
		ID: SessionID,
		RevocationReason: sql.NullString{
			String: string(revocationReason),
			Valid:  revocationReason != "",
		},
	})
}

func (r *Repo) RevokeSessions(ctx context.Context, userID uuid.UUID, revocationReason domain.RevocationReason) error {
	return r.queries.RevokeSessions(ctx, postgres.RevokeSessionsParams{
		UserID: userID,
		RevocationReason: sql.NullString{
			String: string(revocationReason),
			Valid:  revocationReason != "",
		},
	})
}

func (r *Repo) MarkSessionsCompromised(ctx context.Context, userID uuid.UUID) error {
	return r.queries.MarkSessionsCompromised(ctx, userID)
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
		ExpiresAt:        session.ExpiresAt,
		RevokedAt:        revokedAt,
		RevocationReason: domain.RevocationReason(session.RevocationReason.String),
		CompromisedAt:    compromisedAt,
	}
}
