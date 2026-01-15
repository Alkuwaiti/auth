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
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFsa3V3YWl0aXFhc2ltNEBnbWFpbC5jb20iLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTliYThjMC1jOTQ1LTc3ZTMtOTRkNC1kODBiODE5YWQ4ZGUiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc2ODQ5NTMwMywiaWF0IjoxNzY4NDk0NDAzfQ.uqsQ1b89xLpuwqEfvBaxR2pc1f0X3CvYDI2u8g1LY0g",
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

	res, err := client.DeleteUser(ctx, &authv1.DeleteUserRequest{
		UserId: "019b8ef4-13ae-7d79-b280-44cb474d43f2",
		Reason: "USER_IS_BOT",
		Note:   "Not one of us",
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
