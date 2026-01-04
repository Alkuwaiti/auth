package audit

import (
	"context"
	"database/sql"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type repo struct {
	queries *postgres.Queries
}

func NewRepo(queries *postgres.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) CreateAuditLog(ctx context.Context, input CreateAuditLogInput) error {
	var userID uuid.NullUUID
	if input.UserID != nil {
		userID = uuid.NullUUID{
			UUID:  *input.UserID,
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

	if err := r.queries.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
		UserID:    userID,
		Action:    input.Action,
		IpAddress: ip,
		UserAgent: ua,
	}); err != nil {
		return err
	}

	return nil
}
