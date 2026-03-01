package repository

import (
	"context"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type Event struct {
	ID          uuid.UUID
	AggregateID string
	Payload     []byte
	RetryCount  int
}

func (r *Repo) CreateOutboxEvent(ctx context.Context, outboxEvent domain.OutboxEvent) error {
	return r.queries.CreateOutboxEvent(ctx, postgres.CreateOutboxEventParams{
		AggregateType: string(outboxEvent.AggregateType),
		AggregateID:   outboxEvent.AggregateID,
		EventType:     outboxEvent.EventType,
		Payload:       outboxEvent.Payload,
	})
}
