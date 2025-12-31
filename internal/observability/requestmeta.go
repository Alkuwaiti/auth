package observability

import "log/slog"

type RequestMeta struct {
	XForwardedFor string
	RequestID     string
	IPAddress     string
	UserAgent     string
	TraceID       string
	SpanID        string
	RequestMethod string
}

func (m RequestMeta) LogAttrs() []slog.Attr {
	attrs := make([]slog.Attr, 0, 8)

	if m.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", m.RequestID))
	}
	if m.IPAddress != "" {
		attrs = append(attrs, slog.String("ip", m.IPAddress))
	}
	if m.XForwardedFor != "" {
		attrs = append(attrs, slog.String("x_forwarded_for", m.XForwardedFor))
	}
	if m.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", m.UserAgent))
	}
	if m.TraceID != "" {
		attrs = append(attrs, slog.String("trace_id", m.TraceID))
	}
	if m.SpanID != "" {
		attrs = append(attrs, slog.String("span_id", m.SpanID))
	}
	if m.RequestMethod != "" {
		attrs = append(attrs, slog.String("request_method", m.RequestMethod))
	}

	return attrs
}
