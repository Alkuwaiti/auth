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

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/repository"
	"github.com/alkuwaiti/auth/internal/config"
	"github.com/alkuwaiti/auth/internal/crypto"
	"github.com/alkuwaiti/auth/internal/db"
	"github.com/alkuwaiti/auth/internal/flags"
	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/alkuwaiti/auth/internal/server/grpc"
	googlesocial "github.com/alkuwaiti/auth/internal/social/google"
	"github.com/alkuwaiti/auth/internal/tokens"
	"github.com/alkuwaiti/shared/observability/logging"
	"github.com/alkuwaiti/shared/observability/tracing"
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
	flag.Parse()

	cfg := config.Load(strings.ToLower(*envFlag))

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

	flags := flags.New(flags.Config{
		RefreshTokensEnabled: cfg.RefreshEnabled,
	})

	tokens := tokens.New(tokens.Config{
		JWTKey:   []byte(cfg.JWTKey),
		Issuer:   name,
		Audience: name,
	})

	keyBytes, err := hex.DecodeString(cfg.AESKey)
	if err != nil {
		panic("error decoding the AES key")
	}

	c := crypto.NewAESCrypto(keyBytes)

	multifactor := mfa.NewService(c, mfa.Config{
		AppName: cfg.AppName,
	})

	authRepo := repository.NewRepo(dbConn)

	googleProvider := googlesocial.NewService(googlesocial.Config{
		ClientID:     cfg.GoogleConfig.ClientID,
		ClientSecret: cfg.GoogleConfig.ClientSecret,
		RedirectURL:  cfg.GoogleConfig.RedirectURL,
		StateSecret:  cfg.GoogleConfig.StateSecret,
	})

	authService := auth.NewService(authRepo,
		flags,
		tokens,
		multifactor,
		googleProvider,
		auth.Config{
			MaxChallengeAttempts: cfg.MaxChallengeAttempts,
			FrontendOrigin:       cfg.FrontendOrigin,
			Domain:               cfg.Domain,
		})

	port := 8081

	authInterceptor := grpc.NewAuthInterceptor(tokens)

	requestMetaInterceptor := grpc.RequestMetaUnaryInterceptor

	stepUpInterceptor := grpc.NewStepUpInterceptor(tokens, authService)

	srv := grpc.NewServer(authService, grpc.Config{
		Host: "", // listen on all interfaces ":8081"
		Port: port,
	}, authInterceptor.Unary(), requestMetaInterceptor(), stepUpInterceptor.Unary())

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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slog.InfoContext(ctx, "Shutting down server")
	if err := srv.Stop(shutdownCtx); err != nil {
		panic(err)
	}

	slog.InfoContext(ctx, "Server stopped")
}
