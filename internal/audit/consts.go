package audit

type Action string

const (
	ActionCreateUser     Action = "create_user"
	ActionLogout         Action = "logout"
	ActionLogin          Action = "login"
	ActionPasswordChange Action = "password_change"
	// TODO: need to add these.
	ActionSessionRevoked     Action = "session_revoked"
	ActionSessionCompromised Action = "session_compromised"
)
