CREATE TABLE mfa_backup_codes (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  code_hash TEXT NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
  UNIQUE (user_id, code_hash)
);
