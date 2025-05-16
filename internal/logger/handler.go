package logger

import (
	"context"
	"log/slog"

	"github.com/henrywhitaker3/ctxgen"
)

type Handler struct {
	slog.Handler
}

func NewHandler(h slog.Handler) *Handler {
	return &Handler{
		Handler: h,
	}
}

func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	if req, ok := ctxgen.ValueOk[string](ctx, "request_id"); ok {
		record.AddAttrs(slog.String("request_id", req))
	}
	if trace, ok := ctxgen.ValueOk[string](ctx, "trace_id"); ok {
		record.AddAttrs(slog.String("trace_id", trace))
	}
	return h.Handler.Handle(ctx, record)
}

var _ slog.Handler = &Handler{}
