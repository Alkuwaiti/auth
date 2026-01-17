// Package authz provides components to be used in app for authorization.
package authz

type Role string

type Capability string

const (
	CanDeleteUser    Capability = "user.delete"
	CanRevokeSession Capability = "session.revoke"
	CanAssignRole    Capability = "role.assign"
)
