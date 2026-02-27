DROP TABLE IF EXISTS social_accounts;

ALTER TABLE users
ALTER COLUMN password_hash
SET
  NOT NULL;
