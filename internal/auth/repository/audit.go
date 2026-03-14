package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

func (r *Repo) CreateAuditLog(ctx context.Context, input domain.CreateAuditLogInput) error {
	var userID uuid.NullUUID
	if input.UserID != nil {
		userID = uuid.NullUUID{
			UUID:  *input.UserID,
			Valid: true,
		}
	}

	var actorID uuid.NullUUID
	if input.ActorID != nil {
		actorID = uuid.NullUUID{
			UUID:  *input.ActorID,
			Valid: true,
		}
	}

	var ip sql.NullString
	if input.IPAddress != nil {
		ip = sql.NullString{
			String: *input.IPAddress,
			Valid:  true,
		}
	}

	var ua sql.NullString
	if input.UserAgent != nil {
		ua = sql.NullString{
			String: *input.UserAgent,
			Valid:  true,
		}
	}

	var ctxJSON pqtype.NullRawMessage
	if input.Context != nil {
		b, err := json.Marshal(input.Context)
		if err != nil {
			return err
		}

		ctxJSON = pqtype.NullRawMessage{
			RawMessage: b,
			Valid:      true,
		}
	}

	return r.queries.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
		UserID:    userID,
		ActorID:   actorID,
		Action:    string(input.Action),
		Context:   ctxJSON,
		IpAddress: ip,
		UserAgent: ua,
	})
}
