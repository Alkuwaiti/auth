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
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTljMmUyNC02NTUyLTdhNGMtOTNmNS1iMTE0YzBiNGM2NWUiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc3MDM3NTQwMywiaWF0IjoxNzcwMzc0NTAzfQ.UsEpq1LMg7rDpjj5Ahm4F7VyJ9xmRGQsF6bbMfOjMno",
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

	res, err := client.VerifyStepUpChallenge(ctx, &authv1.VerifyStepUpChallengeRequest{
		ChallengeId: "c3a52471-d3b1-41ad-8ac1-faeddc0e5fff",
		Code:        "341917",
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
