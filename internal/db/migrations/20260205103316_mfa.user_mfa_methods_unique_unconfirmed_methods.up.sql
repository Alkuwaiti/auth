-- Only one unconfirmed method per type
CREATE UNIQUE INDEX ux_user_unconfirmed_mfa_method ON user_mfa_methods (user_id, type)
WHERE
  confirmed_at IS NULL;
