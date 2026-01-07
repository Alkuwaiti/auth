package audit

import (
	"database/sql"

	"github.com/alkuwaiti/auth/internal/db/postgres"
)

func NewTestAuditService(db *sql.DB) *service {
	auditRepo := NewRepo(postgres.New(db))
	return NewService(auditRepo)
}
