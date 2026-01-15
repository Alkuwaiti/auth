package audit

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
