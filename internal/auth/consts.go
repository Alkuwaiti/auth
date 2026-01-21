package auth

import "github.com/alkuwaiti/auth/internal/apperrors"

type RevocationReason string

const (
	RevocationSessionCompromised RevocationReason = "user session compromised"
	RevocationSessionRotation    RevocationReason = "rotated session"
	RevocationLogout             RevocationReason = "logout"
	RevocationPasswordChange     RevocationReason = "password changed"
	RevocationUserDeleted        RevocationReason = "user deleted"
)

type DeletionReason string

const (
	DeletionUserBot     DeletionReason = "USER_IS_BOT"
	DeletionUserRequest DeletionReason = "USER_REQUEST"
	DeletionAdminAction DeletionReason = "ADMIN_ACTION"
)

func (d DeletionReason) Validate() error {
	switch d {
	case DeletionUserBot, DeletionUserRequest, DeletionAdminAction:
		return nil
	default:
		return &apperrors.ValidationError{Field: "deletion reason", Msg: "invalid deletion reason"}
	}
}

type MFAMethodType string

const (
	MFATOTP MFAMethodType = "totp"
)

type ChallengeType string

const (
	ChallengeLogin  ChallengeType = "login"
	ChallengeStepUp ChallengeType = "step_up"
)
