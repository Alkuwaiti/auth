// Package outbox houses worker that would pull from the outbox table and send to kafka.
package outbox

import (
	"context"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/repository"
	"github.com/alkuwaiti/auth/internal/infra/kafka"
	"github.com/google/uuid"
)

type worker struct {
	Repo     repo
	Config   Config
	producer *kafka.Producer
	interval time.Duration
}

func NewWorker(repo repo, Config Config) *worker {
	Config.DLQTopic = Config.Topic + ".dlq"
	return &worker{
		Repo:   repo,
		Config: Config,
	}
}

type repo interface {
	GetUnpublishedEvents(ctx context.Context, numberOfEvents int) ([]repository.Event, error)
	MarkAsPublished(ctx context.Context, eventID uuid.UUID) error
	MarkAsFailed(ctx context.Context, eventID uuid.UUID) error
	IncrementRetry(ctx context.Context, eventID uuid.UUID, err error) error
}

type Config struct {
	Topic    string
	DLQTopic string
}

func (w *worker) Start(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.process(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (w *worker) process(ctx context.Context) {
	events, err := w.Repo.GetUnpublishedEvents(ctx, 100)
	if err != nil {
		slog.ErrorContext(ctx, "error getting unpublished events", "err", err)
		return
	}

	for _, e := range events {
		if err = w.producer.Publish(ctx, w.Config.Topic, e.AggregateID, e.Payload); err != nil {
			if retryErr := w.Repo.IncrementRetry(ctx, e.ID, err); retryErr != nil {
				slog.ErrorContext(ctx, "error incrementing retry", "err", err)
			}

			if e.RetryCount+1 >= 5 {
				w.producer.Publish(ctx, w.Config.DLQTopic, e.AggregateID, e.Payload)
				w.Repo.MarkAsFailed(ctx, e.ID)
			}
		}

		if err = w.Repo.MarkAsPublished(ctx, e.ID); err != nil {
			slog.ErrorContext(ctx, "failed to mark event as published", "err", err)
		}
	}
}
