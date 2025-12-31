package observability

import (
	"context"
	"log/slog"
	"os"
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
	if meta, ok := ctx.Value(RequestMetaKey).(RequestMeta); ok {
		r.AddAttrs(meta.LogAttrs()...)
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

	handler := NewContextHandler(base)

	logger := slog.New(handler).
		With(
			slog.String("service", name),
			slog.String("env", environment),
		)

	slog.SetDefault(logger)

}
