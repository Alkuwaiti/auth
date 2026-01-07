package audit

import (
	"context"
	"database/sql"

	"github.com/alkuwaiti/auth/internal/core"
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

func (r *repo) CreateAuditLog(ctx context.Context, input CreateAuditLogInput) (core.AuditLog, error) {
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

	auditLog, err := r.queries.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
		UserID:    userID,
		Action:    string(input.Action),
		IpAddress: ip,
		UserAgent: ua,
	})
	if err != nil {
		return core.AuditLog{}, err
	}

	return toModel(auditLog), nil
}

func toModel(auditLog postgres.AuthAuditLog) core.AuditLog {
	return core.AuditLog{
		UserID:    auditLog.UserID.UUID,
		Action:    auditLog.Action,
		IPAddress: auditLog.IpAddress.String,
		UserAgent: auditLog.UserAgent.String,
		CreatedAt: auditLog.CreatedAt.Time,
	}
}
