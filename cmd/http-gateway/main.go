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
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()

	authClient := authv1.NewAuthServiceClient(conn)

	handler := NewHandler(authClient)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/google/login", handler.GoogleLogin)
	mux.HandleFunc("/auth/google/callback", handler.GoogleCallback)
	mux.HandleFunc("/auth/passkey/register/options", handler.StartPasskeyGeneration)
	mux.HandleFunc("/auth/passkey/register/verify", handler.VerifyPasskeyRegistration)
	mux.HandleFunc("/auth/passkey/authenticate/options", handler.StartPasskeyAuthentication)
	mux.HandleFunc("/auth/passkey/authenticate/verify", handler.VerifyPasskeyAuthentication)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      corsMiddleware(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("HTTP gateway running on :8080")
	log.Fatal(server.ListenAndServe())
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
