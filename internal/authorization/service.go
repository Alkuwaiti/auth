package authz

import "slices"

type service struct{}

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

func New() *service {
	return &service{}
}

func (s *service) ResolveCapabilities(roles []string) map[Capability]struct{} {
	caps := make(map[Capability]struct{})
	for _, role := range roles {
		for _, c := range roleCapabilities[role] {
			caps[c] = struct{}{}
		}
	}
	return caps
}

func (s *service) CanWithRoles(roles []string, cap Capability) bool {
	for _, role := range roles {
		if slices.Contains(roleCapabilities[role], cap) {
			return true
		}
	}

	return false
}
