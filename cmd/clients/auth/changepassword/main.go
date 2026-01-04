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
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFsa3V3YWl0aXFhc2ltM0BnbWFpbC5jb20iLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTliODQ5MS00YWM2LTc1N2EtOGE0ZS03NjdkYjE2MmI1MGQiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc2NzQ1NjcyOSwiaWF0IjoxNzY3NDU1ODI5fQ.52Dg2LhUp6cadu-1K0mhHU4swXhrkiFdHy6yCdG-INY",
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "2.2.2.2",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	client := auth.Must(ctx, "localhost:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.ChangePassword(ctx, &authv1.ChangePasswordRequest{
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
