// Package outbox houses worker that would pull from the outbox table and send to kafka.
package outbox

import (
	"context"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/infra/kafka"
)

type worker struct {
	Repo     repo
	Config   Config
	producer *kafka.Producer
	interval time.Duration
}

func NewWorker(repo repo, Config Config) *worker {
	return &worker{
		Repo:   repo,
		Config: Config,
	}
}

type repo interface {
	GetUnpublishedEvents(ctx context.Context, numberOfEvents int) ([]auth.Event, error)
	MarkAsPublished(ctx context.Context, aggregateID string) error
}

type Config struct {
	Topic string
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
			slog.ErrorContext(ctx, "failed to publish event", "err", err)
		}

		if err = w.Repo.MarkAsPublished(ctx, e.AggregateID); err != nil {
			slog.ErrorContext(ctx, "failed to mark event as published", "err", err)
		}
	}
}
