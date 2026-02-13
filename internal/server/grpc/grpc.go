// Package grpc handles everything grpc server related.
package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type server struct {
	authv1.UnsafeAuthServiceServer

	srv         *grpc.Server
	authService authService
	cfg         Config
}

type authService interface {
	Login(ctx context.Context, email, password string) (auth.LoginResult, error)
	RefreshToken(ctx context.Context, refreshToken string) (auth.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	ChangePassword(ctx context.Context, oldPassword, newPassword string) error
	RegisterUser(context.Context, auth.RegisterUserInput) (domain.User, error)
	DeleteUser(ctx context.Context, input auth.DeleteUserInput) error
	EnrollMFAMethod(ctx context.Context, methodType domain.MFAMethodType) (auth.EnrollmentResult, error)
	ConfirmMFAMethod(ctx context.Context, methodID uuid.UUID, code string) ([]string, error)
	CompleteLoginMFA(ctx context.Context, challengeID uuid.UUID, code string) (auth.TokenPair, error)
	CreateStepUpChallenge(ctx context.Context, methodType domain.MFAMethodType, scope domain.ChallengeScope) (auth.CreateStepUpChallengeResponse, error)
	VerifyStepUpChallenge(ctx context.Context, challengeID uuid.UUID, code string) (auth.VerifyStepUpChallengeResponse, error)
}

type Config struct {
	Host string
	Port int
}

func (c Config) String() string {
	return fmt.Sprintf("%s: %d", c.Host, c.Port)
}

func NewServer(
	authService authService,
	cfg Config,
	interceptors ...grpc.UnaryServerInterceptor,
) *server {

	if authService == nil {
		panic("auth service is nil")
	}

	if cfg.Port <= 0 {
		panic(fmt.Sprintf("invalid port: %d", cfg.Port))
	}

	serverOpts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	}

	if len(interceptors) > 0 {
		serverOpts = append(
			serverOpts,
			grpc.ChainUnaryInterceptor(interceptors...),
		)
	}

	s := &server{
		cfg:         cfg,
		authService: authService,
		srv:         grpc.NewServer(serverOpts...),
	}

	return s
}

func (s *server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", s.cfg.String())
	if err != nil {
		return err
	}

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
