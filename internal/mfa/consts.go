package mfa

type MFAMethodType string

const (
	MFATOTP MFAMethodType = "totp"
)

func (t MFAMethodType) isValid() error {
	switch t {
	case MFATOTP:
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
