package main

import (
	"context"
	"fmt"
	"log"

	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
)

func main() {
	ctx := context.Background()

	client := Must(ctx, "localhost:8081")

	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	_, err := client.RegisterUser(ctx, &userv1.RegisterUserRequest{
		Username: "qasim",
		Email:    "alkuwaitiqasim@gmail.com",
		Password: "Supersecretpassword1!",
	})

	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("\ndone")
}
