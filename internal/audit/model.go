package audit

import (
	"time"

	"github.com/google/uuid"
)

type CreateAuditLogInput struct {
	UserID    *uuid.UUID
	Action    string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
}
