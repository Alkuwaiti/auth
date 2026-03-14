package domain

import "github.com/google/uuid"

type ChangeEmailRequest struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	NewEmail string
}
