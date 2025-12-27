// Package auth has the auth client stub.
package auth

import (
	"context"
	"fmt"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type client struct {
	authv1.AuthServiceClient
	conn *grpc.ClientConn
}

func (c *client) Close() error {
	return c.conn.Close()
}

func New(pingCtx context.Context, address string) (*client, error) {
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user service grpc client: %w", err)
	}

	return &client{
		AuthServiceClient: authv1.NewAuthServiceClient(conn),
		conn:              conn,
	}, nil
}

func Must(pingCtx context.Context, address string) *client {
	s, err := New(pingCtx, address)
	if err != nil {
		panic(err)
	}
	return s
}
