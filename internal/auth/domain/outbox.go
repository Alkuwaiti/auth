package domain

import (
	"time"

	"github.com/google/uuid"
)

type OutboxEvent struct {
	ID            uuid.UUID
	AggregateType AggregateType
	AggregateID   string
	EventType     string
	Payload       []byte
	CreatedAt     time.Time
	PublishedAt   *time.Time
}

type AggregateType string

var (
	AggregateUser AggregateType = "user"
)
