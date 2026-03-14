package domain

import "github.com/google/uuid"

type ChangeEmailRequest struct {
	NewEmail string
	UserID   uuid.UUID
}
