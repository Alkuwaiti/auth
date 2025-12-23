package main

import (
	"context"
	"fmt"

	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type client struct {
	userv1.UserServiceClient
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
		UserServiceClient: userv1.NewUserServiceClient(conn),
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
