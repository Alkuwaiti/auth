package grpc

// TODO: write a general interceptor for step up tokens, for the functions that require that across other services.

import (
	"context"
	"errors"

	"github.com/alkuwaiti/auth/internal/core"
	"github.com/alkuwaiti/auth/internal/tokens"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var StepUpMethods = map[string]string{
	"/auth.v1.AuthService/DeleteAccount":   "delete_account",
	"/auth.v1.AuthService/ChangePassword":  "change_password",
	"/payments.v1.PaymentService/Transfer": "payment",
}

type StepUpInterceptor struct {
	validator StepUpTokenValidator
}

type StepUpTokenValidator interface {
	ValidateStepUpToken(token string) (*tokens.StepUpClaims, error)
}

func NewStepUpInterceptor(tm StepUpTokenValidator) *StepUpInterceptor {
	return &StepUpInterceptor{validator: tm}
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

		tokenStr, err := extractStepUpToken(ctx)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, "step_up_required")
		}

		claims, err := i.validator.ValidateStepUpToken(tokenStr)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid step-up token")
		}

		if claims.Type != string(tokens.StepUpToken) {
			return nil, status.Error(codes.PermissionDenied, "not a step-up token")
		}

		if claims.Scope != requiredScope {
			return nil, status.Errorf(
				codes.PermissionDenied,
				"insufficient scope: required=%s, got=%s",
				requiredScope, claims.Scope,
			)
		}

		ctx = context.WithValue(ctx, core.StepUpClaimsKey{}, claims)

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
