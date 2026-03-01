package main

import (
	"flag"
	"log/slog"
	"strconv"
	"strings"

	"github.com/alkuwaiti/auth/internal/config"
	"github.com/alkuwaiti/auth/internal/db"
	"github.com/alkuwaiti/auth/pkg/observability/logging"
)

func main() {
	envFlag := flag.String("env", "local", "environment to use (local, dev, staging, prod)")
	jurFlag := flag.String("jur", "", "jur to use (bhr, uae, tur)")
	flag.Parse()

	cfg := config.Load(strings.ToLower(*envFlag), strings.ToLower(*jurFlag))

	level := slog.LevelInfo
	if n, err := strconv.Atoi(cfg.LogLevel); err == nil {
		level = slog.Level(n)
	} else if err = level.UnmarshalText([]byte(cfg.LogLevel)); err != nil && cfg.LogLevel != "" {
		panic(err)
	}

	logging.SetDefaultLogger(level, "kafka-worker", cfg.Environment)

	dbConn, err := db.New(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = dbConn.Close(); err != nil {
			slog.Error("error closing db connection", "err", err)
		}
	}()

}
