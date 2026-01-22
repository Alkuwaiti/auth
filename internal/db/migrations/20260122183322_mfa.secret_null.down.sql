DROP INDEX IF EXISTS ux_user_active_mfa_method;

ALTER TABLE user_mfa_methods
ALTER COLUMN secret_ciphertext
SET
  NOT NULL;
