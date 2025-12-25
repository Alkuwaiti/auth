package grpc

import (
	"context"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
)

func (s *server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	panic("unimplemented")
}
