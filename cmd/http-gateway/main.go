// cmd/http-gateway/main.go
package main

import (
	"log"
	"net/http"
	"time"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.NewClient(
		"127.0.0.1:8081",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	authClient := authv1.NewAuthServiceClient(conn)

	handler := NewHandler(authClient)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/google/login", handler.GoogleLogin)
	mux.HandleFunc("/auth/google/callback", handler.GoogleCallback)
	mux.HandleFunc("/auth/passkey/register/options", handler.StartPasskeyGeneration)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("HTTP gateway running on :8080")
	log.Fatal(server.ListenAndServe())
}
