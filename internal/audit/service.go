// Package audit owns the auditing service
package audit

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/core"
	"github.com/google/uuid"
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

func (s *service) CreateAuditLog(ctx context.Context, input CreateAuditLogInput) error {
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

func (s *service) GetAuditLogByUserID(ctx context.Context, userID uuid.UUID) (core.AuditLog, error) {
	ctx, span := tracer.Start(ctx, "AuthService.GetAuditLogByUserID")
	defer span.End()

	auditLog, err := s.repo.GetAuditLogByUserID(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get audit log")
		slog.ErrorContext(ctx, "failed to get audit log", "err", err)
		return core.AuditLog{}, err
	}

	return auditLog, nil
}
