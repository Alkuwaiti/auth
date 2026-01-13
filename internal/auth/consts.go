package auth

type RevocationReason string

const (
	RevocationSessionCompromised RevocationReason = "user session compromised"
	RevocationSessionRotation    RevocationReason = "rotated session"
	RevocationLogout             RevocationReason = "logout"
	RevocationPasswordChange     RevocationReason = "password changed"
	RevocationUserDeleted        RevocationReason = "user deleted"
)

type DeletionReason string

const (
	DeletionUserBot DeletionReason = "user is a bot"
)

func (d *DeletionReason) validate() error {

	return nil
}
