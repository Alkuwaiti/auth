CREATE TABLE mfa_backup_codes (
  id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid (),
  user_id UUID REFERENCES users (id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
  UNIQUE (user_id, code_hash)
);

CREATE INDEX idx_mfa_backup_codes_code_hash ON mfa_backup_codes (code_hash);
