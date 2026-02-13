// Package repository has all the repo methods.
package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) GetUserBackupCodes(ctx context.Context, userID uuid.UUID) ([]domain.MFABackupCode, error) {
	postgresCodes, err := r.queries.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return nil, err
	}

	return toMFABackupCode(postgresCodes), nil
}

func (r *repo) ConsumeBackupCode(ctx context.Context, tx *sql.Tx, codeID uuid.UUID) error {
	return r.queries.WithTx(tx).ConsumeBackupCode(ctx, codeID)
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

func toMFABackupCode(postgresCodes []postgres.MfaBackupCode) []domain.MFABackupCode {
	backupCodes := make([]domain.MFABackupCode, len(postgresCodes))

	var consumedAt *time.Time
	for i, pg := range postgresCodes {
		if pg.ConsumedAt.Valid {
			consumedAt = &pg.ConsumedAt.Time
		}

		backupCodes[i] = domain.MFABackupCode{
			ID:         pg.ID,
			UserID:     pg.UserID,
			CodeHash:   pg.CodeHash,
			ConsumedAt: consumedAt,
			CreatedAt:  pg.CreatedAt,
		}
	}

	return backupCodes
}
