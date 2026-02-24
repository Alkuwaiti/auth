package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
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

	res, err := h.authClient.CompleteGoogleLogin(ctx, &authv1.CompleteGoogleLoginRequest{
		Code:  code,
		State: state,
	})
	if err != nil {
		http.Error(w, "failed to start google login", http.StatusInternalServerError)
		slog.Error("some error happened", "err", err)
		return
	}

	slog.InfoContext(ctx, "this is the response", "res", res)
}
