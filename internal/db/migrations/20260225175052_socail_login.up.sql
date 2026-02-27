CREATE TABLE social_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  UNIQUE (provider, provider_user_id)
);

ALTER TABLE users
ALTER COLUMN password_hash
DROP NOT NULL;
