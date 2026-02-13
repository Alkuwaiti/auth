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

func (r RevocationReason) String() string {
	return string(r)
}

type DeletionReason string

const (
	DeletionUserBot     DeletionReason = "USER_IS_BOT"
	DeletionUserRequest DeletionReason = "USER_REQUEST"
	DeletionAdminAction DeletionReason = "ADMIN_ACTION"
)

func (d DeletionReason) validate() error {
	switch d {
	case DeletionUserBot, DeletionUserRequest, DeletionAdminAction:
		return nil
	default:
		return &apperrors.ValidationError{
			Field: "deletion reason",
			Msg:   "invalid deletion reason",
		}
	}
}

func (d DeletionReason) String() string {
	return string(d)
}
