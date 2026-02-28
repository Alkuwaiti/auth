CREATE TABLE outbox_events (
  ID UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  published_at TIMESTAMPTZ
);

CREATE INDEX idx_outbox_unpublished ON outbox_events (published_at)
WHERE
  published_at IS NULL;
