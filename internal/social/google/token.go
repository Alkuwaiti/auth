package googlesocial

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

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
