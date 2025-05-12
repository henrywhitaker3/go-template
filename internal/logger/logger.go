package logger

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/henrywhitaker3/go-template/internal/http/common"
)

func Setup(level slog.Level, outputs ...io.Writer) {
	if len(outputs) == 0 {
		outputs = []io.Writer{os.Stdout}
	}
	handler := slog.NewJSONHandler(outputs[0], &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func Logger(ctx context.Context) *slog.Logger {
	log := slog.Default()
	if trace := common.TraceID(ctx); trace != "" {
		log = log.With("trace_id", trace)
	}
	if req := common.ContextID(ctx); req != "" {
		log = log.With("request_id", req)
	}
	return log
}
