package grpc

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/core"
)

type ContextHandler struct {
	next slog.Handler
}

func NewContextHandler(next slog.Handler) slog.Handler {
	return &ContextHandler{next: next}
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	// Extract request metadata
	if meta, ok := ctx.Value(requestMetaKey).(core.RequestMeta); ok {
		r.AddAttrs(
			slog.String("ip", meta.IPAddress),
			slog.String("user_agent", meta.UserAgent),
		)
	}

	return h.next.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{next: h.next.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{next: h.next.WithGroup(name)}
}
