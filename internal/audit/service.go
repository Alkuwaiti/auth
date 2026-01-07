// Package audit owns the auditing service
package audit

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/core"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

type service struct {
	repo *repo
}

func NewService(repo *repo) *service {
	return &service{
		repo,
	}
}

var tracer = otel.Tracer("auth-service/audit")

func (s *service) CreateAuditLog(ctx context.Context, input CreateAuditLogInput) (core.AuditLog, error) {
	ctx, span := tracer.Start(ctx, "AuthService.CreateAuditLog")
	defer span.End()

	auditLog, err := s.repo.CreateAuditLog(ctx, input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create audit log")
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		return core.AuditLog{}, err
	}

	return auditLog, nil
}
