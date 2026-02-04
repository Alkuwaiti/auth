package audit

type AuditAction string

const (
	ActionCreateUser         AuditAction = "create_user"
	ActionLogout             AuditAction = "logout"
	ActionLogin              AuditAction = "login"
	ActionLoginMFA           AuditAction = "login_mfa"
	ActionPasswordChange     AuditAction = "password_change"
	ActionSessionCompromised AuditAction = "session_compromised"
	ActionDeleteUser         AuditAction = "delete_user"
)
