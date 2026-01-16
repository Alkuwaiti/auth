-- Remove role_permissions
DELETE FROM role_permissions
WHERE
  role_id IN (
    SELECT
      id
    FROM
      roles
    WHERE
      name IN ('super_admin', 'admin', 'user')
  )
  AND permission_id IN (
    SELECT
      id
    FROM
      permissions
    WHERE
      name IN (
        '*',
        'auth.user.delete',
        'auth.password.change.self'
      )
  );

-- Remove permissions
DELETE FROM permissions
WHERE
  name IN (
    '*',
    'auth.user.delete',
    'auth.password.change.self'
  );

-- Remove roles
DELETE FROM roles
WHERE
  name IN ('super_admin', 'admin', 'user');
