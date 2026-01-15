package core

import "github.com/alkuwaiti/auth/internal/apperrors"

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
