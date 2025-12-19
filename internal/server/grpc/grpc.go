// Package grpc handles everything grpc server related.
package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/alkuwaiti/auth/internal/user"
	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type server struct {
	// TODO: change these to unimplemented when the time comes.
	userv1.UnsafeUserServiceServer

	srv         *grpc.Server
	userService userService
	cfg         Config
}

type userService interface {
	RegisterUser(context.Context, user.RegisterUserInput) (user.User, error)
}

type Config struct {
	Host string
	Port int
}

func (c Config) String() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func NewServer(cfg Config, userService userService) *server {
	if userService == nil {
		panic("user service is nil")
	}

	if cfg.Port <= 0 {
		panic(fmt.Sprintf("invalid port: %d", cfg.Port))
	}

	return &server{
		cfg:         cfg,
		userService: userService,
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

	s.srv = grpc.NewServer()

	userv1.RegisterUserServiceServer(s.srv, s)

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
