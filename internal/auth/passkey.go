package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"math/big"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// TODO: add tests.

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

	return s.buildOptions(user, challenge, creds), nil
}

func generateChallenge() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func (s *Service) buildOptions(user domain.User, challenge []byte, creds [][]byte) Options {
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
			Name: s.Config.Domain,
			ID:   s.Config.Domain,
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
		slog.ErrorContext(ctx, "error decoding client data", "err", err)
		return err
	}

	if clientData.Origin != s.Config.FrontendOrigin {
		return ErrInvalidOrigin
	}

	if clientData.Type != "webauthn.create" {
		return ErrInvalidClientData
	}

	challengeBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
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

	att, err := decodeAttestation(req.Response.AttestationObject)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding attestation", "err", err)
		return err
	}

	parsed, err := s.parseAuthData(att.AuthData)
	if err != nil {
		slog.ErrorContext(ctx, "error parsing auth data", "err", err)
		return err
	}

	credentialID := parsed.CredentialID
	publicKey := parsed.PublicKey
	signCount := parsed.SignCount

	credID, err := base64.RawURLEncoding.DecodeString(req.RawID)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
		return err
	}

	if !bytes.Equal(credID, credentialID) {
		return ErrCredentialIDMismatch
	}

	if err = s.Repo.CreatePasskey(ctx, userID, credentialID, publicKey, int64(signCount), req.Response.Transports); err != nil {
		slog.ErrorContext(ctx, "error creating passkey", "err", err)
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
		slog.Error("error decoding string", "err", err)
		return data, err
	}

	if len(raw) > 2048 {
		return ClientData{}, ErrInvalidClientData
	}

	if err := json.Unmarshal(raw, &data); err != nil {
		slog.Error("error unmarshaling data", "err", err)
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
		slog.Error("error decoding string", "err", err)
		return nil, err
	}

	var att AttestationObject
	if err := cbor.Unmarshal(raw, &att); err != nil {
		slog.Error("error unmarshaling data", "err", err)
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

func (s *Service) parseAuthData(data []byte) (*ParsedAuthData, error) {
	offset := 32 // skip rpIdHash

	flags := data[offset]
	offset++

	signCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// check attested credential flag
	if flags&0x40 == 0 {
		return nil, ErrNoAttestedData
	}

	expected := sha256.Sum256([]byte(s.Config.Domain))

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

func (s *Service) StartPasskeyAuthentication(ctx context.Context) (AssertionOptions, error) {
	challenge, err := generateChallenge()
	if err != nil {
		slog.ErrorContext(ctx, "error generating challenge", "err", err)
		return AssertionOptions{}, err
	}

	if err = s.Repo.CreateWebAuthnChallenge(ctx, challenge, uuid.NullUUID{}, time.Now().Add(5*time.Minute)); err != nil {
		slog.ErrorContext(ctx, "error creating challenge", "err", err)
		return AssertionOptions{}, err
	}

	return AssertionOptions{
		Challenge:        challenge,
		RpID:             s.Config.Domain,
		UserVerification: "preferred",
	}, nil
}

type AssertionResponseData struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

type AssertionResponse struct {
	ID       string                `json:"id"`
	RawID    string                `json:"rawId"`
	Type     string                `json:"type"`
	Response AssertionResponseData `json:"response"`
}

func (s *Service) VerifyPasskeyAuthentication(ctx context.Context, resp AssertionResponse) (TokenPair, error) {
	credID, err := base64.RawURLEncoding.DecodeString(resp.RawID)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
		return TokenPair{}, err
	}

	authData, err := base64.RawURLEncoding.DecodeString(resp.Response.AuthenticatorData)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
		return TokenPair{}, err
	}

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(resp.Response.ClientDataJSON)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
		return TokenPair{}, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(resp.Response.Signature)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
		return TokenPair{}, err
	}

	if len(authData) < 37 {
		return TokenPair{}, ErrAuthdataShort
	}

	var clientData ClientData
	if err = json.Unmarshal(clientDataJSON, &clientData); err != nil {
		slog.ErrorContext(ctx, "error unmarshaling data", "err", err)
		return TokenPair{}, ErrInvalidClientData
	}

	if clientData.Type != "webauthn.get" {
		return TokenPair{}, ErrInvalidClientData
	}

	challengeBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		slog.ErrorContext(ctx, "error decoding string", "err", err)
		return TokenPair{}, err
	}

	storedChallenge, err := s.Repo.GetWebAuthnChallenge(ctx, challengeBytes)
	if err != nil {
		slog.ErrorContext(ctx, "error getting web auth challenge", "err", err)
		return TokenPair{}, err
	}

	if storedChallenge.ExpiresAt.Before(time.Now()) {
		return TokenPair{}, ErrChallengeExpired
	}

	if !bytes.Equal(storedChallenge.Challenge, challengeBytes) {
		return TokenPair{}, ErrChallengeMismatch
	}

	if clientData.Origin != s.Config.FrontendOrigin {
		return TokenPair{}, ErrInvalidOrigin
	}

	expectedRPIDHash := sha256.Sum256([]byte(s.Config.Domain))

	if !bytes.Equal(authData[:32], expectedRPIDHash[:]) {
		return TokenPair{}, ErrInvalidRPID
	}

	flags := authData[32]

	if flags&0x01 == 0 {
		return TokenPair{}, ErrUserNotPresent
	}

	if flags&0x04 == 0 {
		return TokenPair{}, ErrUserNotVerified
	}

	passkey, err := s.Repo.GetPasskeyByCredentialID(ctx, credID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting passkey by credential ID", "err", err, "credential_id", credID)
		return TokenPair{}, ErrCredentialNotFound
	}

	if err = verifyAssertion(authData, clientDataJSON, signature, passkey.PublicKey); err != nil {
		slog.ErrorContext(ctx, "error verifying assertion", "err", err)
		return TokenPair{}, err
	}

	if len(authData) < 37 {
		return TokenPair{}, ErrAuthdataShort
	}

	signCount := binary.BigEndian.Uint32(authData[33:37])

	err = s.Repo.UpdatePasskeySignCount(ctx, passkey.ID, int64(signCount))
	if err != nil {
		slog.ErrorContext(ctx, "error passkey sign count", "err", err)
		return TokenPair{}, err
	}

	user, err := s.Repo.GetUserByID(ctx, passkey.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting user by id", "err", err)
		return TokenPair{}, err
	}

	return s.finalizeLogin(ctx, user, audit.ActionPasskeyLogin, false)
}

func verifyAssertion(authData, clientDataJSON, signature, publicKey []byte) error {
	clientDataHash := sha256.Sum256(clientDataJSON)

	signedData := make([]byte, 0, len(authData)+32)
	signedData = append(signedData, authData...)
	signedData = append(signedData, clientDataHash[:]...)

	pub, err := parseCOSEPublicKey(publicKey)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(signedData)

	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return ErrInvalidSignature
	}

	return nil
}

func parseCOSEPublicKey(coseKey []byte) (*ecdsa.PublicKey, error) {
	var keyMap map[int]any
	if err := cbor.Unmarshal(coseKey, &keyMap); err != nil {
		slog.Error("error unmarshaling data", "err", err)
		return nil, err
	}

	xBytes := keyMap[-2].([]byte) // COSE standard: -2 = x
	yBytes := keyMap[-3].([]byte) // -3 = y

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return pub, nil
}
