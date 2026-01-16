WITH
  -- insert roles
  super_admin AS (
    INSERT INTO
      roles (name, description)
    VALUES
      (
        'super_admin',
        'for all intents and purposes, this role is dog backwards'
      ) RETURNING id
  ),
  admin AS (
    INSERT INTO
      roles (name, description)
    VALUES
      ('admin', 'regular old admin') RETURNING id
  ),
  user_role AS ( -- changed from 'user' to user_role
    INSERT INTO
      roles (name, description)
    VALUES
      ('user', 'regular old user') RETURNING id
  ),
  -- insert permissions
  perm_all AS (
    INSERT INTO
      permissions (name, description)
    VALUES
      (
        '*',
        'access to everything in the system, intended only for super_admin'
      ) RETURNING id
  ),
  perm_user_delete AS (
    INSERT INTO
      permissions (name, description)
    VALUES
      ('auth.user.delete', 'delete a user') RETURNING id
  ),
  perm_password_change_self AS (
    INSERT INTO
      permissions (name, description)
    VALUES
      (
        'auth.password.change.self',
        'change own password'
      ) RETURNING id
  )
  -- assign permissions to roles
INSERT INTO
  role_permissions (role_id, permission_id)
SELECT
  super_admin.id,
  perm_all.id
FROM
  super_admin,
  perm_all
UNION ALL
SELECT
  admin.id,
  perm_user_delete.id
FROM
  admin,
  perm_user_delete
UNION ALL
SELECT
  user_role.id,
  perm_password_change_self.id
FROM
  user_role,
  perm_password_change_self;
