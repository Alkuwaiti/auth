package auth

import "context"

func (s *Service) BeginGoogleLogin(ctx context.Context) (string, error) {
	state, err := s.googleProvider.GenerateState()
	if err != nil {
		return "", err
	}

	return s.googleProvider.AuthURL(state), nil
}
