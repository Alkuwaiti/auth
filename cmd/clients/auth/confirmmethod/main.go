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
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sImlzcyI6ImF1dGgtc2VydmljZSIsInN1YiI6IjAxOWJmYjc2LTc3YTctNzA2ZC1hYTQyLTYxNjRmMTk5ZWYyNyIsImF1ZCI6WyJhdXRoLXNlcnZpY2UiXSwiZXhwIjoxNzY5NTQxNzc1LCJpYXQiOjE3Njk1NDA4NzV9.sWNVkWoMjYcLIqClxvQmGFi87n5ZhHmqMNaxs1wTnkk",
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

	res, err := client.ConfirmMFAMethod(ctx, &authv1.ConfirmMFAMethodRequest{
		MethodId: "3a821672-b95d-410f-a97c-b618a413821e",
		Code:     "546006",
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
