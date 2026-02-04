-- ===============================
-- user_mfa_methods
-- ===============================
CREATE TABLE user_mfa_methods (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  type VARCHAR(32) NOT NULL,
  -- totp | sms | email | webauthn
  secret_ciphertext BYTEA NOT NULL,
  confirmed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
  UNIQUE (user_id, type)
);

CREATE INDEX idx_user_mfa_methods_user_id ON user_mfa_methods (user_id);

ALTER TABLE user_mfa_methods ADD CONSTRAINT user_mfa_methods_type_check CHECK (type IN ('totp', 'sms', 'email', 'webauthn'));

-- ===============================
-- mfa_challenges
-- ===============================
CREATE TABLE mfa_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  mfa_method_id UUID NOT NULL REFERENCES user_mfa_methods (id) ON DELETE CASCADE,
  challenge_type VARCHAR(32) NOT NULL,
  -- login | step_up
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now ()
);

CREATE INDEX idx_mfa_challenges_user_active ON mfa_challenges (user_id)
WHERE
  consumed_at IS NULL;

CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);

ALTER TABLE mfa_challenges ADD CONSTRAINT mfa_challenges_type_check CHECK (challenge_type IN ('login', 'step_up'));
