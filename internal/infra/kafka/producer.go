// Package kafka hosts kafka related code.
package kafka

import (
	"context"

	"github.com/segmentio/kafka-go"
)

type Producer struct {
	writer *kafka.Writer
}

func NewProducer(brokers []string) *Producer {
	return &Producer{
		writer: &kafka.Writer{
			Addr:     kafka.TCP(brokers...),
			Balancer: &kafka.LeastBytes{},
		},
	}
}

func (p *Producer) Publish(ctx context.Context, topic string, key string, value []byte, headers map[string]string) error {
	var kafkaHeaders []kafka.Header

	for k, v := range headers {
		kafkaHeaders = append(kafkaHeaders, kafka.Header{
			Key:   k,
			Value: []byte(v),
		})
	}

	msg := kafka.Message{
		Headers: kafkaHeaders,
		Topic:   topic,
		Key:     []byte(key),
		Value:   value,
	}

	return p.writer.WriteMessages(ctx, msg)
}
