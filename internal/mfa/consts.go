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

func (t ChallengeType) isValid() bool {
	switch t {
	case ChallengeLogin, ChallengeStepUp:
		return true
	default:
		return false
	}
}

type ChallengeScope string

const (
	ScopeLogin ChallengeScope = "login"
)

func (s ChallengeScope) isValid() bool {
	switch s {
	case ScopeLogin:
		return true
	default:
		return false
	}
}
