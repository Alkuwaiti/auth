// Package grpc handles everything grpc server related.
package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/core"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type server struct {
	// TODO: change these to unimplemented when the time comes.
	authv1.UnsafeAuthServiceServer

	srv         *grpc.Server
	authService authService
	cfg         Config
}

type authService interface {
	Login(ctx context.Context, email, password string) (auth.TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string) (auth.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
	RegisterUser(context.Context, auth.RegisterUserInput) (core.User, error)
	DeleteUser(ctx context.Context, input auth.DeleteUserInput) error
}

type Config struct {
	Host   string
	Port   int
	JWTKey []byte
	Name   string
}

func (c Config) String() string {
	return fmt.Sprintf("%s: %d", c.Host, c.Port)
}

func NewServer(authService authService, cfg Config) *server {
	if authService == nil {
		panic("auth service is nil")
	}

	if cfg.Port <= 0 {
		panic(fmt.Sprintf("invalid port: %d", cfg.Port))
	}

	return &server{
		cfg:         cfg,
		authService: authService,
	}
}

func (s *server) Start(ctx context.Context) error {
	if s.srv != nil {
		return fmt.Errorf("server already started")
	}

	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", s.cfg.String())
	if err != nil {
		return err
	}

	s.srv = grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			RequestMetaInterceptor(),
			AuthUnaryInterceptor(s.cfg.JWTKey, s.cfg.Name, s.cfg.Name),
		),
	)

	authv1.RegisterAuthServiceServer(s.srv, s)

	if err = s.srv.Serve(lis); err != nil {
		return err
	}

	return nil
}

func (s *server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return fmt.Errorf("server not started")
	}

	go func() {
		<-ctx.Done()

		if s.srv != nil {
			slog.InfoContext(ctx, "Stopping server forcefully")
			s.srv.Stop()
			s.srv = nil
		}
	}()

	s.srv.GracefulStop()
	s.srv = nil

	return nil
}

func (s *server) Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
