package logger

import (
	"io"
	"log/slog"
	"os"
)

func Setup(level slog.Level, outputs ...io.Writer) {
	if len(outputs) == 0 {
		outputs = []io.Writer{os.Stdout}
	}
	handler := slog.NewJSONHandler(outputs[0], &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	})
	logger := slog.New(NewHandler(handler))
	slog.SetDefault(logger)
}
