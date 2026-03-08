package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Handler struct {
	authClient authv1.AuthServiceClient
}

func NewHandler(authClient authv1.AuthServiceClient) *Handler {
	return &Handler{authClient: authClient}
}

func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	res, err := h.authClient.BeginGoogleLogin(ctx, &emptypb.Empty{})
	if err != nil {
		http.Error(w, "failed to start google login", http.StatusInternalServerError)
		slog.Error("some error happened", "err", err)
		return
	}

	http.Redirect(w, r, res.AuthUrl, http.StatusFound)
}

func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	res, err := h.authClient.CompleteGoogleLogin(ctx, &authv1.CompleteGoogleLoginRequest{
		Code:  code,
		State: state,
	})
	if err != nil {
		slog.Error("google login failed", "err", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    res.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   15 * 60,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    res.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60,
	})

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) StartPasskeyGeneration(w http.ResponseWriter, r *http.Request) {
	bearer := r.URL.Query().Get("bearer")

	ctx := context.Background()

	md := metadata.New(map[string]string{
		"authorization":       "Bearer " + bearer,
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "2.2.2.2",
		"X-Step-Up-Token":     "",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	res, err := h.authClient.StartPasskeyGeneration(ctx, &emptypb.Empty{})
	if err != nil {
		http.Error(w, "failed to start passkey generation", http.StatusInternalServerError)
		slog.Error("failed to start passkey generation", "err", err)
		return
	}

	out, err := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}.Marshal(res)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		slog.ErrorContext(ctx, "failed to marshal passkey generation response", "err", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(out))
}

func (h *Handler) VerifyPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	bearer := r.URL.Query().Get("bearer")

	ctx := context.Background()

	md := metadata.New(map[string]string{
		"authorization":       "Bearer " + bearer,
		"x-forwarded-for":     "203.0.113.10",
		"x-client-user-agent": "auth-cli/1.0",
		"request-id":          "req-123456",
		"x-client-ip":         "2.2.2.2",
		"X-Step-Up-Token":     "",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	res, err := h.authClient.StartPasskeyGeneration(ctx, &emptypb.Empty{})
	if err != nil {
		http.Error(w, "failed to start passkey generation", http.StatusInternalServerError)
		slog.Error("failed to start passkey generation", "err", err)
		return
	}

	out, err := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}.Marshal(res)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		slog.ErrorContext(ctx, "failed to marshal passkey generation response", "err", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(out))
}
