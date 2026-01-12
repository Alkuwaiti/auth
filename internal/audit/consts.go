package audit

type Action string

const (
	ActionCreateUser         Action = "create_user"
	ActionLogout             Action = "logout"
	ActionLogin              Action = "login"
	ActionPasswordChange     Action = "password_change"
	ActionSessionCompromised Action = "session_compromised"
	ActionDeleteUser         Action = "delete_user"
)
