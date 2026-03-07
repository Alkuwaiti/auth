package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
)

type RP struct {
	ID   string
	Name string
}

type ExcludeCredential struct {
	ID   string
	Type string
}

type UserEntity struct {
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
	User                   UserEntity
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

	challenge, err := generateChallenge()
	if err != nil {
		return Options{}, err
	}

	creds, err := s.Repo.ListPasskeysByUserID(ctx, userID)
	if err != nil {
		return Options{}, err
	}

	if err = s.Repo.CreateWebAuthnChallenge(ctx, challenge, userID, time.Now().Add(5*time.Minute)); err != nil {
		return Options{}, err
	}

	return buildOptions(user, challenge, creds), nil
}

func generateChallenge() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func buildOptions(user domain.User, challenge []byte, creds [][]byte) Options {
	exclude := make([]ExcludeCredential, len(creds))

	for i, c := range creds {
		exclude[i] = ExcludeCredential{
			ID:   base64.RawURLEncoding.EncodeToString(c),
			Type: "public-key",
		}
	}

	return Options{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		RP: RP{
			// TODO: change to config
			Name: "auth-service",
			ID:   "localhost",
		},
		User: UserEntity{
			ID:          base64.RawURLEncoding.EncodeToString(user.ID[:]),
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

type PasskeyResponse struct {
	attestationObject  string
	authenticatorData  string
	clientDataJSON     string
	publicKey          string
	publicKeyAlgorithm int
	transports         []string
}

type VerifyRequest struct {
	AuthenticatorAttachment string
	ID                      string
	RawID                   string
	Response                PasskeyResponse
}

func (s *Service) VerifyPasskeyRegistration(ctx context.Context, req VerifyRequest) error {
	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	storedChallenge, err := s.Repo.GetWebAuthnChallengeByUserID(ctx, userID)
	if err != nil {
		return err
	}

	clientData, err := decodeClientData(req.Response.clientDataJSON)
	if err != nil {
		return err
	}

	if clientData.Challenge != string(storedChallenge) {
		return ErrChallengeMismatch
	}

	// TODO: change this
	if clientData.Origin != "http://localhost:5173" {
		return ErrInvalidOrigin
	}

}

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func decodeClientData(encoded string) (ClientData, error) {
	var data ClientData
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return data, err
	}

	if err := json.Unmarshal(raw, &data); err != nil {
		return data, err
	}

	return data, nil
}
