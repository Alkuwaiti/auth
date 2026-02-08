// Package mfa has mfa logic.
package mfa

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

type service struct {
	MFARepo MFARepo
	crypto  Crypto
	Config  Config
}

var tracer = otel.Tracer("auth-service/mfa")

func NewService(MFARepo MFARepo, crypto Crypto, config Config) *service {
	return &service{
		MFARepo: MFARepo,
		crypto:  crypto,
		Config:  config,
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
func (s *service) CreateChallenge(ctx context.Context, userID, methodID uuid.UUID, challengetype ChallengeType, scope ChallengeScope) (MFAChallenge, error) {
	if ok := challengetype.IsValid(); !ok {
		return MFAChallenge{}, ErrInvalidMFAChallengeType
	}

	if ok := scope.isValid(); !ok {
		return MFAChallenge{}, ErrInvalidMFAChallengeScope
	}

	challenge, err := s.MFARepo.createChallenge(ctx, MFAChallenge{
		MethodID:      methodID,
		UserID:        userID,
		Scope:         string(scope),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		ChallengeType: challengetype,
	})
	if err != nil {
		slog.ErrorContext(ctx, "error creating challenge", "err", err)
		return MFAChallenge{}, err
	}

	return challenge, nil
}

func (s *service) GetMethodByID(ctx context.Context, methodID uuid.UUID) (MFAMethod, error) {
	method, err := s.MFARepo.getMFAMethodByID(ctx, methodID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting method by id", "err", err)
		return MFAMethod{}, err
	}

	return method, nil
}

func (s *service) GetChallengeByID(ctx context.Context, challengeID uuid.UUID) (MFAChallenge, error) {
	challenge, err := s.MFARepo.getChallengeByID(ctx, challengeID)
	if err != nil {
		slog.ErrorContext(ctx, "error getting challenge by id", "err", err)
		return MFAChallenge{}, err
	}

	return challenge, nil
}

func (s *service) GetConfirmedMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (MFAMethod, error) {
	method, err := s.MFARepo.GetConfirmedMFAMethodByType(ctx, userID, methodType)
	if err != nil {
		slog.ErrorContext(ctx, "error getting confirmed mfa methods by type", "err", err)
		return MFAMethod{}, err
	}

	return method, nil
}

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

func (s *service) VerifyAndConsumeChallenge(ctx context.Context, challengeID uuid.UUID, code string) (VerifiedChallenge, error) {
	tx, err := s.MFARepo.beginTx(ctx)
	if err != nil {
		return VerifiedChallenge{}, err
	}
	defer func() {
		if err = tx.Rollback(); err != nil && err != sql.ErrTxDone {
			slog.ErrorContext(ctx, "rollback failed", "err", err)
		}
	}()

	locked, err := s.MFARepo.lockActiveTOTPChallenge(ctx, tx, challengeID)
	if err != nil {
		if errors.Is(err, ErrInvalidMFAChallenge) {
			return VerifiedChallenge{}, &apperrors.InvalidMFACodeError{}
		}

		slog.ErrorContext(ctx, "error locking active totp challenge", "err", err)
		return VerifiedChallenge{}, err
	}

	if locked.Attempts >= s.Config.MaxChallengeAttempts {
		return VerifiedChallenge{}, &apperrors.InvalidMFACodeError{}
	}

	if err := s.VerifyTOTP(ctx, string(locked.SecretCiphertext), code); err != nil {
		if incErr := s.MFARepo.incrementChallengeAttempts(ctx, tx, locked.ChallengeID); incErr != nil {
			return VerifiedChallenge{}, incErr
		}
		return VerifiedChallenge{}, err
	}

	if err := s.MFARepo.consumeChallenge(ctx, tx, locked.ChallengeID); err != nil {
		slog.ErrorContext(ctx, "error consuming challenge", "err", err)
		return VerifiedChallenge{}, err
	}

	if err := tx.Commit(); err != nil {
		slog.ErrorContext(ctx, "error committing transaction", "err", err)
		return VerifiedChallenge{}, err
	}

	return VerifiedChallenge{
		ChallengeID: locked.ChallengeID,
		UserID:      locked.UserID,
		MethodID:    locked.MethodID,
	}, nil
}

func (s *service) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := s.MFARepo.userHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
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
