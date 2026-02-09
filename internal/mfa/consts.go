package mfa

type MFAMethodType string

const (
	MFAMethodTOTP MFAMethodType = "totp"
)

func (t MFAMethodType) IsValid() bool {
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

type ChallengeScope string

const (
	ScopeLogin          ChallengeScope = "login"
	ScopeDeleteAccount  ChallengeScope = "delete_account"
	ScopeChangePassword ChallengeScope = "change_password"
)
