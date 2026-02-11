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
		"authorization":       "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InFhc2ltbUBnbWFpbC5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJzdWIiOiIwMTljNGQ5MC03YmU5LTc4YWUtYTQzYS1hNjZjOGY4MWI1ODEiLCJhdWQiOlsiYXV0aC1zZXJ2aWNlIl0sImV4cCI6MTc3MDgzMTI3OSwiaWF0IjoxNzcwODMwMzc5fQ.3XUT_F_E-0V8_UG9soEztAXCyE9F5Ixchv5meej2tp4",
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "1.1.1.1",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	client := auth.Must(ctx, "127.0.0.1:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.ConfirmMFAMethod(ctx, &authv1.ConfirmMFAMethodRequest{
		MethodId: "add45e2f-b563-42d4-be1f-035b6bdbdca4",
		Code:     "651995",
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
