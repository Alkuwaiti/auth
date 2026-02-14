ALTER TABLE audit_logs
DROP COLUMN actor_id UUID REFERENCES users (id),
DROP COLUMN context JSONB;
