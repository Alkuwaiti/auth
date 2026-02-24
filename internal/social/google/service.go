// Package googlesocial provides google implementation for social login
package googlesocial

import (
	"context"
	"errors"

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
