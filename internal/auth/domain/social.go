package domain

import (
	"time"

	"github.com/google/uuid"
)

type SocialAccount struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Provider       Provider
	ProviderUserID string
	CreatedAt      time.Time
}

type Provider string

var (
	ProviderGoogle Provider = "google"
)
