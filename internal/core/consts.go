package core

import "github.com/alkuwaiti/auth/internal/apperrors"

type DeletionReason string

const (
	DeletionUserBot DeletionReason = "USER_IS_BOT"
)

func (d DeletionReason) Validate() error {
	switch d {
	case DeletionUserBot:
		return nil
	default:
		return &apperrors.ValidationError{Field: "deletion reason", Msg: "invalid deletion reason"}
	}
}
