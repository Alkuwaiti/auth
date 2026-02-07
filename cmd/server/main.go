package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth"
	authz "github.com/alkuwaiti/auth/internal/authorization"
	"github.com/alkuwaiti/auth/internal/config"
	"github.com/alkuwaiti/auth/internal/crypto"
	"github.com/alkuwaiti/auth/internal/db"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/flags"
	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/alkuwaiti/auth/internal/observability/logging"
	"github.com/alkuwaiti/auth/internal/observability/tracing"
	"github.com/alkuwaiti/auth/internal/password"
	"github.com/alkuwaiti/auth/internal/server/grpc"
	"github.com/alkuwaiti/auth/internal/tokens"
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

	logging.SetDefaultLogger(level, name, cfg.Environment)

	tp, err := tracing.InitTracer(
		ctx,
		tracing.Config{
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
		if err = tracing.ShutdownTracer(ctx, tp); err != nil {
			slog.Error("failed to shutdown tracer", "err", err)
		}
	}()

	dbConn, err := db.New(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = dbConn.Close(); err != nil {
			slog.Error("error closing db connection", "err", err)
		}
	}()

	passwords := password.NewService(12)

	queries := postgres.New(dbConn)

	auditRepo := audit.NewRepo(queries)

	auditor := audit.New(auditRepo)

	flags := flags.New(flags.Config{
		RefreshTokensEnabled: cfg.RefreshEnabled,
	})

	authorizer := authz.New()

	tokens := tokens.New(tokens.Config{
		JWTKey:   []byte(cfg.JWTKey),
		Issuer:   name,
		Audience: name,
	})

	mfaRepo := mfa.NewMFARepo(dbConn)

	keyBytes, err := hex.DecodeString(cfg.AESKey)
	if err != nil {
		panic("error decoding the AES key")
	}

	c := crypto.NewAESCrypto(keyBytes)

	multifactor := mfa.NewService(*mfaRepo, c, mfa.Config{
		AppName: cfg.AppName,
	})

	authRepo := auth.NewRepo(dbConn)

	authService := auth.NewService(authRepo, passwords, auditor, authorizer, flags, tokens, multifactor)

	port := 8081

	authInterceptor := grpc.NewAuthInterceptor(tokens)

	requestMetaInterceptor := grpc.NewRequestMetaInterceptor()

	stepUpInterceptor := grpc.NewStepUpInterceptor(tokens, multifactor)

	srv := grpc.NewServer(authService, grpc.Config{
		Host: "", // listen on all interfaces ":8081"
		Port: port,
	}, authInterceptor.Unary(), requestMetaInterceptor.Unary(), stepUpInterceptor.Unary())

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
