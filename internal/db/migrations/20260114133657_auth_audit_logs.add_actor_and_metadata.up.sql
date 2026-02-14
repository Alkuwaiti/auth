ALTER TABLE audit_logs
ADD COLUMN actor_id UUID REFERENCES users (id),
ADD COLUMN context JSONB;
