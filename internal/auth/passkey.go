package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
)

type RP struct {
	Name string
	ID   string
}

type ExcludeCredential struct {
	Type string
	ID   string
}

type User struct {
	ID          string
	Name        string
	DisplayName string
}

type PubKeyCredParam struct {
	Type string
	Alg  int
}

type AuthenticatorSelection struct {
	ResidentKey      string
	UserVerification string
}

type Options struct {
	Challenge              string
	RP                     RP
	User                   User
	PubKeyCredParams       []PubKeyCredParam
	Timeout                int
	Attestation            string
	AuthenticatorSelection AuthenticatorSelection
	ExcludeCredentials     []ExcludeCredential
}

func (s *Service) StartPasskeyGeneration(ctx context.Context) (Options, error) {
	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return Options{}, err
	}

	user, err := s.Repo.GetUserByID(ctx, userID)
	if err != nil {
		return Options{}, err
	}

	raw, _, err := s.TokenManager.GenerateToken()
	if err != nil {
		return Options{}, err
	}

	creds, err := s.Repo.ListPasskeysByUserID(ctx, userID)
	if err != nil {
		return Options{}, err
	}

	// TODO: change to store hashed.
	if err = s.Repo.CreateWebAuthnChallenge(ctx, raw, userID, time.Now().Add(5*time.Minute)); err != nil {
		return Options{}, err
	}

	return buildOptions(user, raw, creds), nil
}

func buildOptions(user domain.User, challenge string, creds [][]byte) Options {
	exclude := make([]ExcludeCredential, len(creds))

	for i, c := range creds {
		exclude[i] = ExcludeCredential{
			ID:   string(c),
			Type: "public-key",
		}
	}

	return Options{
		Challenge: challenge,
		RP: RP{
			Name: "auth-service",
			ID:   "localhost",
		},
		User: User{
			ID:          user.ID.String(),
			Name:        user.Email,
			DisplayName: user.Email,
		},
		PubKeyCredParams: []PubKeyCredParam{
			{Type: "public-key", Alg: -7},
			{Type: "public-key", Alg: -257},
		},
		Timeout:     60000,
		Attestation: "none",
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey:      "preferred",
			UserVerification: "preferred",
		},
		ExcludeCredentials: exclude,
	}
}
