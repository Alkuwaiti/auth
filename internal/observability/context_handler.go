package observability

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/alkuwaiti/auth/internal/core"
)

type ContextHandler struct {
	next slog.Handler
}

func newContextHandler(next slog.Handler) slog.Handler {
	return &ContextHandler{next: next}
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	// Extract request metadata
	if meta, ok := ctx.Value(RequestMetaKeyType{}).(RequestMeta); ok {
		r.AddAttrs(meta.LogAttrs()...)
	}

	if userID, ok := ctx.Value(core.UserIDKey{}).(string); ok {
		r.AddAttrs(slog.String("user_id", userID))
	}

	return h.next.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{next: h.next.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{next: h.next.WithGroup(name)}
}

func SetDefaultLogger(level slog.Level, name, environment string) {
	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	handler := newContextHandler(base)

	logger := slog.New(handler).
		With(
			slog.String("service", name),
			slog.String("env", environment),
		)

	slog.SetDefault(logger)

}
