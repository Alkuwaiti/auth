package grpc

import (
	"context"
	"errors"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/tokens"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var StepUpMethods = map[string]domain.ChallengeScope{
	"/auth.v1.AuthService/DeleteAccount":  domain.ScopeDeleteAccount,
	"/auth.v1.AuthService/ChangePassword": domain.ScopeChangePassword,
}

type StepUpInterceptor struct {
	validator StepUpTokenValidator
	mfaQuery  MFAQuery
}

type StepUpTokenValidator interface {
	ValidateStepUpToken(token string) (*tokens.StepUpClaims, error)
}

type MFAQuery interface {
	UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error)
}

func NewStepUpInterceptor(tm StepUpTokenValidator, mfaQuery MFAQuery) *StepUpInterceptor {
	return &StepUpInterceptor{
		validator: tm,
		mfaQuery:  mfaQuery,
	}
}

func (i *StepUpInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		requiredScope, requiresStepUp := StepUpMethods[info.FullMethod]
		if !requiresStepUp {
			return handler(ctx, req)
		}

		userID, err := contextkeys.UserIDFromContext(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid user id")
		}

		hasMFA, err := i.mfaQuery.UserHasActiveMFAMethod(ctx, userID)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to check mfa status")
		}
		if !hasMFA {
			// skip to next handler
			return handler(ctx, req)
		}

		tokenStr, err := extractStepUpToken(ctx)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, "step_up_required")
		}

		claims, err := i.validator.ValidateStepUpToken(tokenStr)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid step-up token")
		}

		if claims.Scope != requiredScope.String() {
			return nil, status.Errorf(
				codes.PermissionDenied,
				"insufficient scope: required=%s, got=%s",
				requiredScope, claims.Scope,
			)
		}

		ctx = context.WithValue(ctx, contextkeys.StepUpClaimsKey{}, claims)

		return handler(ctx, req)
	}
}

func extractStepUpToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("no metadata")
	}

	values := md.Get("X-Step-Up-Token")
	if len(values) == 0 {
		return "", errors.New("no authorization header")
	}

	return values[0], nil
}
