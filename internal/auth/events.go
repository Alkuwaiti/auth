package auth

import "github.com/google/uuid"

type EventType string

type userRegistered struct {
	UserID uuid.UUID
	Email  string
	EventType
}
