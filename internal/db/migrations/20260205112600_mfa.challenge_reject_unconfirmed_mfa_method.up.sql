-- reject challenges for unconfirmed methods
CREATE OR REPLACE FUNCTION reject_unconfirmed_mfa_method()
RETURNS trigger AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM user_mfa_methods m
    WHERE m.id = NEW.method_id
      AND (
        m.confirmed_at IS NULL
        OR (m.expires_at IS NOT NULL AND m.expires_at <= now())
      )
  ) THEN
    RAISE EXCEPTION
      'cannot create challenge for unconfirmed or expired MFA method'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reject_unconfirmed_mfa_method
BEFORE INSERT ON mfa_challenges
FOR EACH ROW
EXECUTE FUNCTION reject_unconfirmed_mfa_method();
