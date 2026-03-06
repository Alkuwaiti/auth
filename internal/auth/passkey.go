package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/pkg/contextkeys"
)

type Options struct {
	Challenge string
	RP        struct {
		Name string
		ID   string
	}
	User struct {
		ID          string
		Name        string
		DisplayName string
	}
	PubKeyCredParams []struct {
		Type string
		Alg  int
	}
	Timeout                int
	Attestation            string
	AuthenticatorSelection struct {
		ResidentKey      string
		UserVerification string
	}
	ExcludeCredentials []struct {
		Type string
		ID   string
	}
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

	if err = s.Repo.CreateWebAuthnChallenge(ctx, raw, userID, time.Now().Add(5*time.Minute)); err != nil {
		return Options{}, err
	}

}
