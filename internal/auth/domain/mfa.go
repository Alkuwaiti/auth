// Package domain contains domain models.
package domain

import (
	"time"

	"github.com/google/uuid"
)

type MFABackupCode struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	CodeHash   string
	ConsumedAt *time.Time
	CreatedAt  time.Time
}
