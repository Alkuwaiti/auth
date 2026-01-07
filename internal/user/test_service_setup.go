package user

import (
	"database/sql"

	"github.com/alkuwaiti/auth/internal/db/postgres"
)

func NewTestUserService(db *sql.DB) *service {
	userRepo := NewRepo(postgres.New(db))
	return NewService(userRepo)
}
