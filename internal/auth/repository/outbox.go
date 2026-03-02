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

func (r *Repo) GetUnpublishedEvents(ctx context.Context, numberOfEvents int) ([]Event, error) {
	dbEvents, err := r.queries.GetUnpublishedEvents(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]Event, len(dbEvents))

	for i, e := range dbEvents {
		events[i] = Event{
			ID:          e.ID,
			AggregateID: e.AggregateID,
			Payload:     e.Payload,
			RetryCount:  int(e.RetryCount),
		}
	}

	return events, nil
}

func (r *Repo) MarkBatchAsPublished(ctx context.Context, uuids []uuid.UUID) error {
	return r.queries.MarkBatchAsPublished(ctx, uuids)
}

func (r *Repo) MarkBatchAsFailed(ctx context.Context, uuids []uuid.UUID) error {
	return r.queries.MarkBatchAsFailed(ctx, uuids)
}

func (r *Repo) BatchIncrementRetry(ctx context.Context, uuids []uuid.UUID) error {
	return r.queries.BatchIncrementRetry(ctx, uuids)
}
