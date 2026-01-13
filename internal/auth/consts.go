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
	DeletionUserBot DeletionReason = "USER_IS_BOT"
)

func (d DeletionReason) validate() error {
	switch d {
	case DeletionUserBot:
		return nil
	default:
		return &apperrors.ValidationError{Field: "deletion reason", Msg: "invalid deletion reason"}
	}
}
