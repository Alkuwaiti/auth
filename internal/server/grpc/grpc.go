// Package grpc handles everything grpc server related.
package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/observability"
	"github.com/alkuwaiti/auth/internal/user"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type server struct {
	// TODO: change these to unimplemented when the time comes.
	userv1.UnsafeUserServiceServer
	authv1.UnsafeAuthServiceServer

	srv         *grpc.Server
	userService userService
	authService authService
	cfg         Config
}

type userService interface {
	RegisterUser(context.Context, user.RegisterUserInput) (user.User, error)
}

type authService interface {
	Login(ctx context.Context, email, password string, meta observability.RequestMeta) (auth.TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string, meta observability.RequestMeta) (auth.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	ChangePassword(ctx context.Context, oldPassword, newPassword string) error
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

func NewServer(cfg Config, userService userService, authService authService) *server {
	if userService == nil {
		panic("user service is nil")
	}

	if authService == nil {
		panic("auth service is nil")
	}

	if cfg.Port <= 0 {
		panic(fmt.Sprintf("invalid port: %d", cfg.Port))
	}

	return &server{
		cfg:         cfg,
		userService: userService,
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
			LoggingInterceptor(),
			AuthUnaryInterceptor(s.cfg.JWTKey, s.cfg.Name, s.cfg.Name),
		),
	)

	userv1.RegisterUserServiceServer(s.srv, s)
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
