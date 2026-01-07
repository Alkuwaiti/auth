// Package testutil makes it easier to spin up needed instances for integration tests.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

type TestDB struct {
	DB        *sql.DB
	Terminate func(context.Context) error
}

func NewPostgres(ctx context.Context) (*TestDB, error) {
	pg, err := postgres.Run(
		ctx,
		"postgres:16",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
	)
	if err != nil {
		return nil, err
	}

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := waitForDB(ctx, db); err != nil {
		return nil, err
	}

	return &TestDB{
		DB: db,
		Terminate: func(ctx context.Context) error {
			return pg.Terminate(ctx)
		},
	}, nil
}

func waitForDB(ctx context.Context, db *sql.DB) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("database did not become ready in time")
		case <-ticker.C:
			if err := db.PingContext(ctx); err == nil {
				return nil
			}
		}
	}
}
