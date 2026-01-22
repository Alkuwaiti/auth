package mfa

type MFAMethodType string

const (
	MFAMethodTOTP MFAMethodType = "totp"
)

func (t MFAMethodType) isValid() error {
	switch t {
	case MFAMethodTOTP:
		return nil
	default:
		return ErrInvalidMFAMethodType
	}
}

type ChallengeType string

const (
	ChallengeLogin  ChallengeType = "login"
	ChallengeStepUp ChallengeType = "step_up"
)
