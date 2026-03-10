package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		"x-step-up-token":     "",
	})

	ctx = metadata.NewOutgoingContext(ctx, md)

	var req struct {
		ID                      string `json:"id"`
		RawID                   string `json:"rawId"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		Response                struct {
			AttestationObject  string   `json:"attestationObject"`
			AuthenticatorData  string   `json:"authenticatorData"`
			ClientDataJSON     string   `json:"clientDataJSON"`
			PublicKey          string   `json:"publicKey"`
			PublicKeyAlgorithm int32    `json:"publicKeyAlgorithm"`
			Transports         []string `json:"transports"`
		} `json:"response"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		slog.ErrorContext(ctx, "failed to decode passkey registration body", "err", err)
		return
	}

	res, err := h.authClient.VerifyPasskeyRegistration(ctx, &authv1.VerifyPasskeyRegistrationRequest{
		Id:                      req.ID,
		RawId:                   req.RawID,
		AuthenticatorAttachment: req.AuthenticatorAttachment,
		Response: &authv1.PasskeyResponse{
			AttestationObject:  req.Response.AttestationObject,
			AuthenticatorData:  req.Response.AuthenticatorData,
			ClientDataJson:     req.Response.ClientDataJSON,
			PublicKey:          req.Response.PublicKey,
			PublicKeyAlgorithm: req.Response.PublicKeyAlgorithm,
			Transports:         req.Response.Transports,
		},
	})
	if err != nil {
		http.Error(w, "failed to verify passkey registration", http.StatusInternalServerError)
		slog.Error("failed to verify passkey registration", "err", err)
		return
	}

	out, err := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}.Marshal(res)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		slog.ErrorContext(ctx, "failed to marshal passkey verification response", "err", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (h *Handler) StartPasskeyAuthentication(w http.ResponseWriter, r *http.Request) {
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

	res, err := h.authClient.StartPasskeyAuthentication(ctx, &emptypb.Empty{})
	if err != nil {
		http.Error(w, "failed to start passkey authentication", http.StatusInternalServerError)
		slog.Error("failed to start passkey authentication", "err", err)
		return
	}

	out, err := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}.Marshal(res)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		slog.ErrorContext(ctx, "failed to marshal passkey authentication response", "err", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(out))
}

func (h *Handler) VerifyPasskeyAuthentication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bearer := r.URL.Query().Get("bearer")

	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"authorization", "Bearer "+bearer,
		"x-forwarded-for", "203.0.113.10",
		"x-client-user-agent", "auth-cli/1.0",
		"request-id", "req-123456",
		"x-client-ip", "2.2.2.2",
	))

	var req verifyPasskeyAuthRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.ErrorContext(ctx, "failed to decode passkey auth body", "err", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	authData, err := base64ToBytes(req.Response.AuthenticatorData)
	if err != nil {
		http.Error(w, "invalid authenticatorData", http.StatusBadRequest)
		return
	}

	clientData, err := base64ToBytes(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "invalid clientDataJSON", http.StatusBadRequest)
		return
	}

	signature, err := base64ToBytes(req.Response.Signature)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	userHandle, err := base64ToBytes(req.Response.UserHandle)
	if err != nil && req.Response.UserHandle != "" {
		http.Error(w, "invalid userHandle", http.StatusBadRequest)
		return
	}

	res, err := h.authClient.VerifyPasskeyAuthentication(ctx, &authv1.VerifyPasskeyAuthenticationRequest{
		Id:    req.ID,
		RawId: req.RawID,
		Type:  req.Type,
		Response: &authv1.AssertionResponseData{
			AuthenticatorData: authData,
			ClientDataJson:    clientData,
			Signature:         signature,
			UserHandle:        userHandle,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to verify passkey authentication", "err", err)
		http.Error(w, "failed to verify passkey authentication", http.StatusInternalServerError)
		return
	}

	out, err := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}.Marshal(res)
	if err != nil {
		slog.ErrorContext(ctx, "failed to marshal response", "err", err)
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

type verifyPasskeyAuthRequest struct {
	ID    string `json:"id"`
	RawID string `json:"rawId"`
	Type  string `json:"type"`

	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

func base64ToBytes(v string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(v)
}
