package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/alkuwaiti/auth/cmd/clients/user"
	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	ctx := context.Background()

	client := user.Must(ctx, "localhost:8081")
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.RegisterUser(ctx, &userv1.RegisterUserRequest{
		Username: "qasim",
		Email:    "alkuwaitiqasim@gmail.com",
		Password: "Supersecretpassword1!",
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
