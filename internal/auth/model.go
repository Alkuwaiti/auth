package auth

import (
	"time"

	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	RefreshExpiresAt time.Time
	UserID           uuid.UUID
}
