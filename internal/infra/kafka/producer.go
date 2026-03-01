// Package kafka hosts kafka related code.
package kafka

import (
	"context"

	"github.com/segmentio/kafka-go"
)

type producer struct {
	writer *kafka.Writer
}

func NewProducer(brokers []string) *producer {
	return &producer{
		writer: &kafka.Writer{
			Addr:     kafka.TCP(brokers...),
			Balancer: &kafka.LeastBytes{},
		},
	}
}

func (p *producer) Publish(ctx context.Context, topic string, key string, value []byte) error {
	return p.writer.WriteMessages(ctx, kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: value,
	})
}
