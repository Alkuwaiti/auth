package repository

import (
	"context"
	"database/sql"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/db/postgres"
)

type Repo struct {
	db      *sql.DB
	queries *postgres.Queries
}

func NewRepo(db *sql.DB) *Repo {
	return &Repo{
		db:      db,
		queries: postgres.New(db),
	}
}

func (r *Repo) WithTx(ctx context.Context, fn func(auth.Repo) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	txRepo := &Repo{
		db:      r.db,
		queries: r.queries.WithTx(tx),
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	return fn(txRepo)
}
