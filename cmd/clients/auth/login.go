package main

import (
	"context"
	"fmt"
	"log"

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

	client := Must(ctx, "localhost:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.Login(ctx, &authv1.LoginRequest{
		Email:    "alkuwaitiqasim@gmail.com",
		Password: "supersecretpassword1!",
	})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(res)
	fmt.Println("done")
}
