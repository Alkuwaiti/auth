package mfa

type MFAMethodType string

const (
	MFATOTP MFAMethodType = "totp"
)

type ChallengeType string

const (
	ChallengeLogin  ChallengeType = "login"
	ChallengeStepUp ChallengeType = "step_up"
)
