package mfa

import (
	"database/sql"

	"github.com/alkuwaiti/auth/internal/db/postgres"
)

type MFARepo struct {
	queries *postgres.Queries
	db      *sql.DB
}

func NewMFARepo(db *sql.DB) *MFARepo {
	return &MFARepo{
		db:      db,
		queries: postgres.New(db),
	}
}
