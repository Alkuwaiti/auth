// Package repository has all the repo methods.
package repository

import (
	"context"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *Repo) GetUserBackupCodes(ctx context.Context, userID uuid.UUID) ([]domain.MFABackupCode, error) {
	postgresCodes, err := r.queries.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return nil, err
	}

	return toMFABackupCode(postgresCodes), nil
}

func (r *Repo) ConsumeBackupCode(ctx context.Context, codeID uuid.UUID) error {
	return r.queries.ConsumeBackupCode(ctx, codeID)
}

func (r *Repo) InsertBackupCodes(ctx context.Context, userID uuid.UUID, hashedCodes []string) error {
	return r.queries.InsertBackupCodes(ctx, postgres.InsertBackupCodesParams{
		UserID:  userID,
		Column2: hashedCodes,
	})
}

func (r *Repo) DeleteUserBackupCodes(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DeleteUserBackupCodes(ctx, userID)
}

func toMFABackupCode(postgresCodes []postgres.MfaBackupCode) []domain.MFABackupCode {
	backupCodes := make([]domain.MFABackupCode, len(postgresCodes))

	for i, pg := range postgresCodes {
		backupCodes[i] = domain.MFABackupCode{
			ID:       pg.ID,
			CodeHash: pg.CodeHash,
		}
	}

	return backupCodes
}
