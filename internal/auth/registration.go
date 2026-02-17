package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/auth/repository"
	authz "github.com/alkuwaiti/auth/internal/authorization"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) RegisterUser(ctx context.Context, input RegisterUserInput) (domain.User, error) {
	ctx, span := tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	meta := contextkeys.RequestMetaFromContext(ctx)

	span.SetAttributes(
		attribute.String("user.username", input.Username),
		attribute.String("user.email", input.Email),
	)

	if err := input.validate(); err != nil {
		return domain.User{}, err
	}

	if err := s.Passwords.Validate(input.Password); err != nil {
		return domain.User{}, err
	}

	newPasswordHash, err := s.Passwords.Hash(input.Password)
	if err != nil {
		span.RecordError(err)
		return domain.User{}, err
	}

	user, err := s.Repo.CreateUser(ctx, input.Username, input.Email, newPasswordHash)
	if err != nil {
		if errors.Is(err, repository.ErrRecordAlreadyExists) {
			return domain.User{}, &apperrors.BadRequestError{
				Field: "user",
				Msg:   "user already exists",
			}
		}
		return domain.User{}, &apperrors.InternalError{
			Msg: "failed to register a user",
			Err: err,
		}
	}

	if err = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &user.ID,
		Action:    audit.ActionCreateUser,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.WarnContext(ctx, "failed to create audit log", "err", err)
		return domain.User{}, err
	}

	span.SetAttributes(
		attribute.String("user.id", user.ID.String()),
	)

	span.SetStatus(codes.Ok, "user registered")
	return user, nil
}

func (s *Service) DeleteUser(ctx context.Context, input DeleteUserInput) error {
	ctx, span := tracer.Start(ctx, "AuthService.DeleteUser")
	defer span.End()

	actorID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	roles, err := contextkeys.UserRolesFromContext(ctx)
	if err != nil {
		return err
	}

	if !s.authorizer.CanWithRoles(roles, authz.CanDeleteUser) {
		userID, _ := contextkeys.UserIDFromContext(ctx)
		slog.ErrorContext(ctx, "forbidden user attempt", "user_id", userID)
		return &apperrors.ForbiddenError{}
	}

	if err := input.validate(); err != nil {
		slog.ErrorContext(ctx, "failed to validate deletion reason", "err", err)
		return err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	// TODO: split up
	if err := s.Repo.DeleteUserAndRevokeSessions(ctx, input.UserID, input.DeletionReason, domain.RevocationUserDeleted); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return &apperrors.BadRequestError{
				Field: "user uuid",
				Msg:   "User not found or already deleted",
			}
		}
		slog.ErrorContext(ctx, "failed to delete user and revoke sessions", "err", err)
		return err
	}

	if err := s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &input.UserID,
		ActorID:   &actorID,
		Action:    audit.ActionDeleteUser,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
		Context: audit.AuditContext{
			"deletion": map[string]any{
				"reason": string(input.DeletionReason),
				"note":   input.Note,
			},
		},
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		return err
	}

	span.SetStatus(codes.Ok, "user deleted and sessions revoked")

	return nil
}
