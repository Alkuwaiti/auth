package auth

import (
	"context"
	"database/sql"

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
	for i, backupCode := range backupCodes {
		backupCodes[i] = MFABackupCode{
			ID:         backupCode.ID,
			UserID:     backupCode.UserID,
			CodeHash:   backupCode.CodeHash,
			ConsumedAt: backupCode.ConsumedAt,
			CreatedAt:  backupCode.CreatedAt,
		}
	}

	return backupCodes
}
