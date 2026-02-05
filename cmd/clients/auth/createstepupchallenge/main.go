package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/alkuwaiti/auth/cmd/clients/auth"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	ctx := context.Background()

	md := metadata.New(map[string]string{
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sImlzcyI6ImF1dGgtc2VydmljZSIsInN1YiI6IjAxOWMyZTI0LTY1NTItN2E0Yy05M2Y1LWIxMTRjMGI0YzY1ZSIsImF1ZCI6WyJhdXRoLXNlcnZpY2UiXSwiZXhwIjoxNzcwMzAxNzY1LCJpYXQiOjE3NzAzMDA4NjV9.O-TgVZJBqEJYa0_wahgrL_-JYd3_KKWaewSUB6uhA5Y",
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

	res, err := client.CreateStepUpChallenge(ctx, &authv1.CreateStepUpChallengeRequest{
		MethodType: "totp",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	out, err := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: true,
	}.Marshal(res)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
