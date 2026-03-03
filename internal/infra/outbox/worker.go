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
	Producer *kafka.Producer
}

func NewWorker(repo repo, producer *kafka.Producer, config Config) *worker {
	if config.DLQTopic == "" {
		config.DLQTopic = config.Topic + ".dlq"
	}

	return &worker{
		Repo:     repo,
		Config:   config,
		Producer: producer,
	}
}

type repo interface {
	GetUnpublishedEvents(ctx context.Context, numberOfEvents int) ([]repository.Event, error)
	MarkBatchAsPublished(ctx context.Context, uuids []uuid.UUID) error
	MarkBatchAsFailed(ctx context.Context, uuids []uuid.UUID) error
	BatchIncrementRetry(ctx context.Context, uuids []uuid.UUID) error
}

type Config struct {
	Topic    string
	DLQTopic string
	Interval time.Duration
}

func (w *worker) Start(ctx context.Context) {
	ticker := time.NewTicker(w.Config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Info("processing...")
			w.process(ctx)
		case <-ctx.Done():
			return
		}
	}
}

const EventType string = "EventType"

func (w *worker) process(ctx context.Context) {
	events, err := w.Repo.GetUnpublishedEvents(ctx, 100)
	if err != nil {
		slog.ErrorContext(ctx, "error getting unpublished events", "err", err)
		return
	}

	var toPublish []uuid.UUID
	var toFail []uuid.UUID
	var toRetry []uuid.UUID

	for _, e := range events {
		err := w.Producer.Publish(ctx, w.Config.Topic, e.AggregateID, e.Payload, map[string]string{
			EventType: e.EventType,
		})
		if err != nil {

			if e.RetryCount+1 >= 5 {
				err = w.Producer.Publish(ctx, w.Config.DLQTopic, e.AggregateID, e.Payload, map[string]string{
					EventType: e.EventType,
				})
				if err != nil {
					slog.Error("error occured when publishing", "err", err)
				}
				toFail = append(toFail, e.ID)
			} else {
				toRetry = append(toRetry, e.ID)
			}

			continue
		}

		toPublish = append(toPublish, e.ID)
	}

	if len(toPublish) > 0 {
		_ = w.Repo.MarkBatchAsPublished(ctx, toPublish)
	}

	if len(toRetry) > 0 {
		_ = w.Repo.BatchIncrementRetry(ctx, toRetry)
	}

	if len(toFail) > 0 {
		_ = w.Repo.MarkBatchAsFailed(ctx, toFail)
	}
}
