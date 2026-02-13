package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) getUserBackupCodes(ctx context.Context, userID uuid.UUID) ([]MFABackupCode, error) {
	postgresCodes, err := r.queries.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return nil, err
	}

	return toMFABackupCode(postgresCodes), nil
}

func (r *repo) consumeBackupCode(ctx context.Context, tx *sql.Tx, codeID uuid.UUID) error {
	return r.queries.WithTx(tx).ConsumeBackupCode(ctx, codeID)
}

func toMFABackupCode(postgresCodes []postgres.MfaBackupCode) []MFABackupCode {
	backupCodes := make([]MFABackupCode, len(postgresCodes))

	var consumedAt *time.Time
	for i, pg := range postgresCodes {
		if pg.ConsumedAt.Valid {
			consumedAt = &pg.ConsumedAt.Time
		}

		backupCodes[i] = MFABackupCode{
			ID:         pg.ID,
			UserID:     pg.UserID,
			CodeHash:   pg.CodeHash,
			ConsumedAt: consumedAt,
			CreatedAt:  pg.CreatedAt,
		}
	}

	return backupCodes
}
