package repository

import (
	"context"
	"database/sql"

	"github.com/alkuwaiti/auth/internal/db/postgres"
)

type repo struct {
	db      *sql.DB
	queries *postgres.Queries
}

func NewRepo(db *sql.DB) *repo {
	return &repo{
		db:      db,
		queries: postgres.New(db),
	}
}

func (r *repo) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

func (r *repo) ExecTx(ctx context.Context, fn func(*postgres.Queries) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	qtx := r.queries.WithTx(tx)

	if err := fn(qtx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}
