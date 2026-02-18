package contextkeys

import "errors"

var (
	ErrMissingUserID          error = errors.New("missing user id in context")
	ErrMissingUserRoles       error = errors.New("missing user roles in context")
	ErrMissingUserEmail       error = errors.New("missing user email in context")
	ErrMissingrequestMetadata error = errors.New("missing request metadata in context")
)
