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
