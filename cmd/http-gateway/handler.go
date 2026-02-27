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
	w.Write([]byte("login successful"))

}
