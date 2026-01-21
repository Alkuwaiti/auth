// Package mfa has mfa logic.
package mfa

type Service struct {
	methods    MFAMethodRepo
	challenges MFAChallengeRepo
	// totp       totp.Verifier
	// tokens     token.Manager
}
