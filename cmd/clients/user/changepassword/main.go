package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/alkuwaiti/auth/cmd/clients/user"
	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	ctx := context.Background()

	md := metadata.New(map[string]string{
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFsa3V3YWl0aXFhc2ltQGdtYWlsLmNvbSIsImlzcyI6ImF1dGgtc2VydmljZSIsInN1YiI6ImE2YjY4NmQyLTg2OGItNGZhZC1iMzQ4LTRkN2ViMmEyNTc3ZSIsImF1ZCI6WyJhdXRoLXNlcnZpY2UiXSwiZXhwIjoxNzY3MjkyNTc0LCJpYXQiOjE3NjcyOTE2NzR9.lr5h_TA0FTWlN7_wN8MLb5evBYQGPhfaKjoiwcC4pIw",
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "2.2.2.2",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	client := user.Must(ctx, "localhost:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.ChangePassword(ctx, &userv1.ChangePasswordRequest{
		OldPassword: "Supersecretpassword1!",
		NewPassword: "Supersecretpassword1!",
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
