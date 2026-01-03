package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/config"
	"github.com/alkuwaiti/auth/internal/db"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/observability"
	"github.com/alkuwaiti/auth/internal/password"
	"github.com/alkuwaiti/auth/internal/server/grpc"
	"github.com/alkuwaiti/auth/internal/user"
)

var (
	commit  string
	ref     string
	version string
	name    = "auth-service"
)

func main() {
	ctx := context.Background()

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

	observability.SetDefaultLogger(level, name, cfg.Environment)

	tp, err := observability.InitTracer(
		ctx,
		observability.Config{
			ServiceName:  name,
			Environment:  cfg.Environment,
			Version:      version,
			OTLPEndpoint: cfg.OTLPEndpoint,
		},
	)
	if err != nil {
		log.Fatal("failed to initialize tracer:", err)
	}
	defer func() {
		if err = observability.ShutdownTracer(ctx, tp); err != nil {
			slog.Error("failed to shutdown tracer", "err", err)
		}
	}()

	dbConn, err := db.New(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	defer dbConn.Close()

	passwordService := password.NewService(12)

	userRepo := user.NewRepo(postgres.New(dbConn))

	userService := user.NewService(userRepo)

	authRepo := auth.NewRepo(dbConn)

	authService := auth.NewService(authRepo, userService, passwordService, auth.Config{
		Issuer:   name,
		Audience: name,
		JWTKey:   []byte(cfg.JWTKey),
	})

	port := 8081

	srv := grpc.NewServer(grpc.Config{
		Host:   "", // listen on all interfaces ":8081"
		Port:   port,
		JWTKey: []byte(cfg.JWTKey),
		Name:   name,
	}, userService, authService)

	slog.InfoContext(ctx, "starting grpc server", "port", port, "commit", commit, "ref", ref, "version", version)
	go func(ctx context.Context) {
		if err := srv.Start(ctx); err != nil {
			slog.ErrorContext(ctx, "Server error", "error", err)
			os.Exit(1)
		}
	}(ctx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// This hangs the server.
	<-sigChan

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slog.InfoContext(ctx, "Shutting down server")
	if err := srv.Stop(ctx); err != nil {
		panic(err)
	}

	slog.InfoContext(ctx, "Server stopped")
}
