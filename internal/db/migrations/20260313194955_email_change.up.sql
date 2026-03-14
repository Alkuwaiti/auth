CREATE TABLE email_change_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  new_email TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
);

CREATE INDEX idx_email_change_requests_user_id ON email_change_requests (user_id);

CREATE INDEX idx_email_change_requests_token_hash ON email_change_requests (token_hash);
