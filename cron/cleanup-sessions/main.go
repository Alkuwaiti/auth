package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"

	_ "github.com/lib/pq"
)

const batchSize = 1000

func main() {
	dbURL := os.Getenv("DATABASEURL")
	if dbURL == "" {
		panic("DATABASE_URL is not set")
	}

	ctx := context.Background()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		slog.Error("failed to connect to DB", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err = db.Close(); err != nil {
			slog.ErrorContext(ctx, "error closing db connection", "err", err)
		}
	}()

	totalDeleted := 0

	for {
		res, err := db.ExecContext(ctx, `
            DELETE FROM sessions
            WHERE id IN (
                SELECT id FROM sessions
                WHERE expires_at <= NOW()
                LIMIT $1
            )
        `, batchSize)
		if err != nil {
			slog.ErrorContext(ctx, "failed to delete expired sessions", "err", err)
			os.Exit(1)
		}

		rows, _ := res.RowsAffected()
		totalDeleted += int(rows)
		if rows == 0 {
			break
		}
	}

	slog.Info("Expired session cleanup completed, total deleted: %d", "totalDeleted", totalDeleted)
}
