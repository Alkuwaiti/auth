package domain

type OutboxEvent struct {
	AggregateType AggregateType
	AggregateID   string
	EventType     string
	Payload       []byte
}

type AggregateType string

var (
	AggregateUser AggregateType = "user"
)
