package mfa

type MFAMethodType string

const (
	MFAMethodTOTP MFAMethodType = "totp"
)

func (t MFAMethodType) isValid() bool {
	switch t {
	case MFAMethodTOTP:
		return true
	default:
		return false
	}
}

type ChallengeType string

const (
	ChallengeLogin  ChallengeType = "login"
	ChallengeStepUp ChallengeType = "step_up"
)
