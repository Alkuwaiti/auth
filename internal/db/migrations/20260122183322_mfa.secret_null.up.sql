ALTER TABLE user_mfa_methods
ALTER COLUMN secret_ciphertext
DROP NOT NULL;

CREATE UNIQUE INDEX ux_user_active_mfa_method ON user_mfa_methods (user_id, type)
WHERE
  confirmed_at IS NOT NULL;
