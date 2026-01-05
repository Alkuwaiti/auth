package audit

import (
	"github.com/google/uuid"
)

type CreateAuditLogInput struct {
	UserID    *uuid.UUID
	Action    Action
	IPAddress *string
	UserAgent *string
}
