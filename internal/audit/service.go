// Package audit owns the auditing service
package audit

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

type auditor struct {
	repo *repo
}

func New(repo *repo) *auditor {
	return &auditor{
		repo,
	}
}

var tracer = otel.Tracer("auth-service/audit")

func (s *auditor) CreateAuditLog(ctx context.Context, input CreateAuditLogInput) error {
	ctx, span := tracer.Start(ctx, "AuthService.CreateAuditLog")
	defer span.End()

	if err := s.repo.CreateAuditLog(ctx, input); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create audit log")
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		return err
	}

	return nil
}
