// Package authz provides components to be used in app for authorization.
package authz

type Role string

const (
	UserRole   Role = "user"
	AdminRole  Role = "admin"
	SuperAdmin Role = "super_admin"
)
