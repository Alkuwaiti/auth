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
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTljMzdmZC04MTA5LTc0YjctYWU3My03ZWYxYTZiNWRhNmYiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc3MDQ3MDcyMSwiaWF0IjoxNzcwNDY5ODIxfQ.LxpVzTx1hy0m8QznsKobu7wdIZXDiMLsqdBhS4hOqKs",
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "2.2.2.2",
		"X-Step-Up-Token":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJzY29wZSI6ImNoYW5nZV9wYXNzd29yZCIsInR5cGUiOiJzdGVwX3VwIiwiaXNzIjoiYXV0aC1zZXJ2aWNlIiwic3ViIjoiMDE5YzM3ZmQtODEwOS03NGI3LWFlNzMtN2VmMWE2YjVkYTZmIiwiYXVkIjpbImF1dGgtc2VydmljZSJdLCJleHAiOjE3NzA0NzA0MTUsImlhdCI6MTc3MDQ3MDExNX0.OLW6rqIa7uPt_jcLz1P0_a15ryiJPDzYOo-OiYFfuzE",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	client := auth.Must(ctx, "127.0.0.1:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		OldPassword: "Supersecretpassword1!",
		NewPassword: "Supersecretpassword1!!",
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
