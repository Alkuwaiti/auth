package authz

import "slices"

var roleCapabilities = map[string][]Capability{
	"super_admin": {
		CanAssignRole,
		CanDeleteUser,
		CanRevokeSession,
	},
	"admin": {
		CanDeleteUser,
	},
}

func ResolveCapabilities(roles []string) map[Capability]struct{} {
	caps := make(map[Capability]struct{})
	for _, role := range roles {
		for _, c := range roleCapabilities[role] {
			caps[c] = struct{}{}
		}
	}
	return caps
}

func CanWithRoles(roles []string, cap Capability) bool {
	for _, role := range roles {
		if slices.Contains(roleCapabilities[role], cap) {
			return true
		}
	}

	return false
}
