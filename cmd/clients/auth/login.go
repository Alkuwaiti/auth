package main

import (
	"context"
	"fmt"
	"log"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
)

func main() {
	ctx := context.Background()

	client := Must(ctx, "localhost:8081")

	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	res, err := client.Login(ctx, &authv1.LoginRequest{
		Email:    "alkuwaitiqasim@gmail.com",
		Password: "Supersecretpassword1!",
	})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(res)

	fmt.Printf("\ndone")
}
