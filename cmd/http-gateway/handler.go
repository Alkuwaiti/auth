package main

import (
	"context"
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
		return
	}

	http.Redirect(w, r, res.AuthUrl, http.StatusFound)
}
