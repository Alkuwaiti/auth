package main

import (
	"context"
	"fmt"
	"log"

	"github.com/alkuwaiti/auth/cmd/clients/auth"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc/metadata"
)

func main() {
	ctx := context.Background()

	md := metadata.New(map[string]string{
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "1.1.1.1",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	client := auth.Must(ctx, "localhost:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.RefreshToken(ctx, &authv1.RefreshTokenRequest{
		RefreshToken: "NAQUhO2pXBfy6dV_PFXi_7OOuvyDkO439mhP4ZSTl5A=",
	})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(res)
	fmt.Println("done")
}
