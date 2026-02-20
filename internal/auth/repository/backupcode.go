// Package repository has all the repo methods.
package repository

import (
	"context"
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

func (r *repo) ConsumeBackupCode(ctx context.Context, codeID uuid.UUID) error {
	return r.queries.ConsumeBackupCode(ctx, codeID)
}

func (r *repo) InsertBackupCodes(ctx context.Context, userID uuid.UUID, hashedCodes []string) error {
	return r.queries.InsertBackupCodes(ctx, postgres.InsertBackupCodesParams{
		UserID:  userID,
		Column2: hashedCodes,
	})
}

func (r *repo) DeleteUserBackupCodes(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DeleteUserBackupCodes(ctx, userID)
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
