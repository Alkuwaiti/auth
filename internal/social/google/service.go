// Package googlesocial provides google implementation for social login
package googlesocial

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

type service struct {
	oauthConfig *oauth2.Config
	stateSecret string
}

type Config struct {
	ClientID, ClientSecret, RedirectURL, StateSecret string
}

type GoogleUser struct {
	Subject, Email, Name string
}

func NewService(config Config) *service {
	return &service{
		oauthConfig: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email", "profile"},
		},
		stateSecret: config.StateSecret,
	}
}

func (s *service) AuthURL(state string) string {
	return s.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *service) ExchangeCode(ctx context.Context, code string) (GoogleUser, error) {
	token, err := s.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return GoogleUser{}, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return GoogleUser{}, errors.New("no id_token")
	}

	payload, err := idtoken.Validate(ctx, rawIDToken, s.oauthConfig.ClientID)
	if err != nil {
		return GoogleUser{}, err
	}

	email := payload.Claims["email"].(string)
	subject := payload.Subject
	name := payload.Claims["name"].(string)

	return GoogleUser{
		Subject: subject,
		Email:   email,
		Name:    name,
	}, nil
}

type oauthState struct {
	Nonce     string    `json:"n"`
	ExpiresAt time.Time `json:"exp"`
}

func (s *service) GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	state := oauthState{
		Nonce:     base64.RawStdEncoding.EncodeToString(b),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)

	h := hmac.New(sha256.New, []byte(s.stateSecret))
	h.Write([]byte(payloadEnc))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return payloadEnc + "." + signature, nil
}

func (s *service) ValidateState(state string) error {
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		return ErrInvalidState
	}

	payloadEnc := parts[0]
	signature := parts[1]

	h := hmac.New(sha256.New, []byte(s.stateSecret))
	h.Write([]byte(payloadEnc))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return ErrInvalidStateSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEnc)
	if err != nil {
		return err
	}

	var st oauthState
	if err := json.Unmarshal(payloadBytes, &st); err != nil {
		return err
	}

	if time.Now().After(st.ExpiresAt) {
		return ErrStateExpired
	}

	return nil
}
