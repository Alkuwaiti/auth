// Package mfa has mfa logic.
package mfa

import (
	"context"
	"crypto/rand"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

type service struct {
	crypto Crypto
	Config Config
}

var tracer = otel.Tracer("auth-service/mfa")

func NewService(crypto Crypto, config Config) *service {
	return &service{
		crypto: crypto,
		Config: config,
	}
}

type Crypto interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type EnrollmentResult struct {
	Method   MFAMethod
	SetupURI string
}

// TODO: figure out how to target which method type when creating a challenge.
// TODO: add rate limiting

func (s *service) VerifyTOTP(ctx context.Context, secret, code string) error {
	ctx, span := tracer.Start(ctx, "mfaService.verifyTOTP")
	defer span.End()

	secretBytes, err := s.crypto.Decrypt([]byte(secret))
	if err != nil {
		slog.ErrorContext(ctx, "error decrypting", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "error encrypting")
		return err
	}

	valid, err := totp.ValidateCustom(code, string(secretBytes), time.Now(), totp.ValidateOpts{
		Period: 30,
		Skew:   1, // ±30s
		Digits: otp.DigitsSix,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error validating totp", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "error validating totp")
		return err
	}

	if !valid {
		return &apperrors.BadRequestError{
			Field: "code",
			Msg:   "invalid code",
		}
	}

	return nil
}

func (s *service) GenerateTOTPKey(email string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      s.Config.AppName,
		AccountName: email,
	})
}

func (s *service) GenerateEncryptedSecret(key *otp.Key) ([]byte, error) {
	return s.crypto.Encrypt([]byte(key.Secret()))

}

func (s *service) GenerateBackupCodes(n int, hash func(string) (string, error)) (plain []string, hashed []string, err error) {
	plain = make([]string, 0, n)
	hashed = make([]string, 0, n)

	for range n {
		raw, err := generateBackupCode(8)
		if err != nil {
			return nil, nil, err
		}

		formatted := formatBackupCode(raw)

		hash, err := hash(formatted)
		if err != nil {
			return nil, nil, err
		}

		plain = append(plain, formatted)
		hashed = append(hashed, hash)
	}

	return plain, hashed, nil
}

// no O, I, 0, 1 → avoids confusion
var backupCodeAlphabet = []rune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

func generateBackupCode(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	runes := make([]rune, length)
	for i := range b {
		runes[i] = backupCodeAlphabet[int(b[i])%len(backupCodeAlphabet)]
	}

	return string(runes), nil
}

func formatBackupCode(raw string) string {
	// e.g. ABCDEFGH → ABCD-EFGH
	if len(raw) != 8 {
		return raw
	}
	return raw[:4] + "-" + raw[4:]
}
