CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
);

CREATE TABLE roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE user_roles (
  user_id UUID REFERENCES users (id) ON DELETE CASCADE,
  role_id UUID REFERENCES roles (id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ DEFAULT NOW (),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE role_permissions (
  role_id UUID REFERENCES roles (id) ON DELETE CASCADE,
  permission_id UUID REFERENCES permissions (id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID REFERENCES users (id) ON DELETE CASCADE,
  refresh_token_hash VARCHAR(255) NOT NULL,
  user_agent TEXT,
  ip_address VARCHAR(45),
  created_at TIMESTAMPTZ DEFAULT NOW (),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE auth_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID REFERENCES users (id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  type VARCHAR(50) NOT NULL, -- e.g., 'password_reset', 'email_verify'
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW ()
);

CREATE TABLE two_factor_methods (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID REFERENCES users (id) ON DELETE CASCADE,
  method VARCHAR(50) NOT NULL, -- 'totp', 'sms', 'email'
  secret TEXT,
  phone_number VARCHAR(20),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW ()
);

CREATE TABLE social_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID REFERENCES users (id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL, -- 'google', 'github', 'facebook'
  provider_user_id VARCHAR(255) NOT NULL,
  access_token TEXT,
  refresh_token TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW ()
);

CREATE TABLE auth_audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
  user_id UUID REFERENCES users (id),
  action VARCHAR(100), -- login, logout, password_change, token_refresh
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW ()
);
