package repository

import (
	"context"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
)

func (r *repo) CreateOutboxEvent(ctx context.Context, outboxEvent domain.OutboxEvent) error {
	return r.queries.CreateOutboxEvent(ctx, postgres.CreateOutboxEventParams{
		AggregateType: string(outboxEvent.AggregateType),
		AggregateID:   outboxEvent.AggregateID,
		EventType:     outboxEvent.EventType,
		Payload:       outboxEvent.Payload,
	})
}
