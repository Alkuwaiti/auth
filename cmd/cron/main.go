package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/alkuwaiti/auth/internal/config"
	"github.com/alkuwaiti/auth/internal/db"
	"github.com/alkuwaiti/auth/pkg/observability/logging"
)

const batchSize = 1000

var tables = []string{
	"sessions",
	"email_verification_tokens",
	"password_reset_tokens",
	"mfa_challenges",
	"user_mfa_methods",
	"webauthn_challenges",
	"email_change_requests",
}

func main() {
	envFlag := flag.String("env", "local", "environment to use (local, dev, staging, prod)")
	flag.Parse()

	cfg := config.Load(strings.ToLower(*envFlag))

	level := slog.LevelInfo
	if n, err := strconv.Atoi(cfg.LogLevel); err == nil {
		level = slog.Level(n)
	} else if err = level.UnmarshalText([]byte(cfg.LogLevel)); err != nil && cfg.LogLevel != "" {
		panic(err)
	}

	logging.SetDefaultLogger(level, "cron-job", cfg.Environment)

	dbConn, err := db.New(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = dbConn.Close(); err != nil {
			slog.Error("error closing db connection", "err", err)
		}
	}()

	ctx := context.Background()

	for {
		deletedThisRound := 0

		for _, table := range tables {
			n, err := deleteExpired(ctx, dbConn, table)
			if err != nil {
				slog.ErrorContext(ctx, "failed deleting expired rows", "table", table, "err", err)
				os.Exit(1)
			}

			deletedThisRound += n
		}

		if deletedThisRound == 0 {
			break
		}
	}

	slog.Info("expired records cleanup complete")
}

func deleteExpired(ctx context.Context, db *sql.DB, table string) (int, error) {
	query := `
		DELETE FROM ` + table + `
		WHERE id IN (
			SELECT id FROM ` + table + `
			WHERE expires_at <= NOW()
			LIMIT $1
		)
	`

	res, err := db.ExecContext(ctx, query, batchSize)
	if err != nil {
		return 0, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if rows > 0 {
		slog.InfoContext(ctx, "deleted expired rows",
			"table", table,
			"count", rows,
		)
	}

	return int(rows), nil
}
