package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
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
		slog.ErrorContext(ctx, "failed to get user by id", "err", err)
		return Options{}, err
	}

	challenge, err := generateChallenge()
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate challenge", "err", err)
		return Options{}, err
	}

	creds, err := s.Repo.ListPasskeysByUserID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list passkeys by user id", "err", err)
		return Options{}, err
	}

	err = s.Repo.CreateWebAuthnChallenge(ctx, challenge, uuid.NullUUID{UUID: userID, Valid: true}, time.Now().Add(5*time.Minute))
	if err != nil {
		slog.ErrorContext(ctx, "failed to create web authn challenge", "err", err)
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
	AttestationObject  string
	AuthenticatorData  string
	ClientDataJSON     string
	PublicKey          string
	PublicKeyAlgorithm int
	Transports         []string
}

type VerifyRequest struct {
	ID                      string
	RawID                   string
	AuthenticatorAttachment string
	Response                PasskeyResponse
}

func (s *Service) VerifyPasskeyRegistration(ctx context.Context, req VerifyRequest) error {
	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	if req.ID != req.RawID {
		return ErrCredentialIDMismatch
	}

	clientData, err := decodeClientData(req.Response.ClientDataJSON)
	if err != nil {
		return err
	}

	challengeBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return err
	}

	storedChallenge, err := s.Repo.GetWebAuthnChallenge(ctx, challengeBytes)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get web authn challenge by user id", "err", err)
		return err
	}

	if storedChallenge.ExpiresAt.Before(time.Now()) {
		return ErrChallengeExpired
	}

	if !bytes.Equal(challengeBytes, storedChallenge.Challenge) {
		return ErrChallengeMismatch
	}

	// TODO: change this
	if clientData.Origin != "http://localhost:5173" {
		return ErrInvalidOrigin
	}

	if clientData.Type != "webauthn.create" {
		return ErrInvalidClientData
	}

	att, err := decodeAttestation(req.Response.AttestationObject)
	if err != nil {
		return err
	}

	parsed, err := parseAuthData(att.AuthData)
	if err != nil {
		return err
	}

	credentialID := parsed.CredentialID
	publicKey := parsed.PublicKey
	signCount := parsed.SignCount

	credID, err := base64.RawURLEncoding.DecodeString(req.RawID)
	if err != nil {
		return err
	}

	if !bytes.Equal(credID, credentialID) {
		return ErrCredentialIDMismatch
	}

	if err = s.Repo.CreatePasskey(ctx, userID, credentialID, publicKey, int64(signCount), req.Response.Transports); err != nil {
		return err
	}

	return nil
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

	if len(raw) > 2048 {
		return ClientData{}, ErrInvalidClientData
	}

	if err := json.Unmarshal(raw, &data); err != nil {
		return ClientData{}, err
	}

	return data, nil
}

type AttestationObject struct {
	Format       string         `cbor:"fmt"`
	AuthData     []byte         `cbor:"authData"`
	AttStatement map[string]any `cbor:"attStmt"`
}

func decodeAttestation(encoded string) (*AttestationObject, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	var att AttestationObject
	if err := cbor.Unmarshal(raw, &att); err != nil {
		return nil, err
	}

	return &att, nil
}

type ParsedAuthData struct {
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
}

// 32  rpIdHash
// 1   flags
// 4   signCount
// 16  AAGUID
// 2   credID length
// N   credID
// N   publicKey

func parseAuthData(data []byte) (*ParsedAuthData, error) {
	offset := 32 // skip rpIdHash

	flags := data[offset]
	offset++

	signCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// check attested credential flag
	if flags&0x40 == 0 {
		return nil, ErrNoAttestedData
	}

	expected := sha256.Sum256([]byte("localhost"))

	if !bytes.Equal(data[:32], expected[:]) {
		return nil, ErrInvalidRPID
	}

	offset += 16 // skip AAGUID

	credIDLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	credentialID := data[offset : offset+int(credIDLen)]
	offset += int(credIDLen)

	publicKey := data[offset:]

	return &ParsedAuthData{
		CredentialID: credentialID,
		PublicKey:    publicKey,
		SignCount:    signCount,
	}, nil
}

type AssertionOptions struct {
	Challenge        []byte
	RpID             string
	UserVerification string
}

// func (s *Service) StartPasskeyAuthentication(ctx context.Context) (AssertionOptions, error) {
// 	challenge, err := generateChallenge()
// 	if err != nil {
// 		return AssertionOptions{}, err
// 	}
// }
