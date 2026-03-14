package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

type CreateAuditLogInput struct {
	UserID    *uuid.UUID
	Action    AuditAction
	IPAddress *string
	UserAgent *string
	Context   AuditContext
	ActorID   *uuid.UUID
}

type AuditContext map[string]any

func (c *AuditContext) Scan(value any) error {
	if value == nil {
		*c = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan AuditContext")
	}

	return json.Unmarshal(bytes, c)
}

func (c AuditContext) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}

type AuditAction string

const (
	ActionCreateUser          AuditAction = "create_user"
	ActionLogout              AuditAction = "logout"
	ActionLogin               AuditAction = "login"
	ActionLoginMFA            AuditAction = "login_mfa"
	ActionPasswordChange      AuditAction = "password_change"
	ActionSessionCompromised  AuditAction = "session_compromised"
	ActionDeleteUser          AuditAction = "delete_user"
	ActionConfirmMFAMethod    AuditAction = "confirm_mfa_method"
	ActionConsumeChallenge    AuditAction = "consume_challenge"
	ActionVerifyEmail         AuditAction = "verify_email"
	ActionPasswordReset       AuditAction = "password_reset"
	ActionGoogleLogin         AuditAction = "google_login"
	ActionGoogleRegisteration AuditAction = "google_registration"
	ActionPasskeyLogin        AuditAction = "passkey_login"
)
