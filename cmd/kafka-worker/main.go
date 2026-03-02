package main

import (
	"context"
	"flag"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/repository"
	"github.com/alkuwaiti/auth/internal/config"
	"github.com/alkuwaiti/auth/internal/db"
	"github.com/alkuwaiti/auth/internal/infra/kafka"
	"github.com/alkuwaiti/auth/internal/infra/outbox"
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

	producer := kafka.NewProducer(cfg.KafkaConfig.Brokers)

	repo := repository.NewRepo(dbConn)

	worker := outbox.NewWorker(repo, producer, outbox.Config{
		Topic:    cfg.KafkaConfig.Topic,
		DLQTopic: cfg.KafkaConfig.DLQTopic,
		Interval: 5 * time.Second,
	})

	ctx := context.Background()

	slog.InfoContext(ctx, "starting kafka worker")

	worker.Start(ctx)
}
