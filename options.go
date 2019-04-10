package objectify

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
)

func Noop() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		fmt.Println("noop option")
		return h
	}
}

func WithJSONFormatter() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Formatter = &logrus.JSONFormatter{
			PrettyPrint: true,
		}
		return h
	}
}

func WithLevelFromEnv(key string) Option {
	return func(h *logrus.Logger) *logrus.Logger {
		level := os.Getenv(key)
		switch {
		case strings.Contains(level, "warn"), strings.Contains(level, "Warn"):
			h.Level = logrus.WarnLevel
		case strings.Contains(level, "debug"), strings.Contains(level, "Debug"):
			h.Level = logrus.DebugLevel
		case strings.Contains(level, "info"), strings.Contains(level, "Info"):
			h.Level = logrus.InfoLevel
		case strings.Contains(level, "fatal"), strings.Contains(level, "Fatal"):
			h.Level = logrus.FatalLevel
		case strings.Contains(level, "error"), strings.Contains(level, "Error"):
			h.Level = logrus.ErrorLevel
		default:
			h.Level = logrus.DebugLevel
		}
		return h
	}
}

func WithTextFormatter(color bool) Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Formatter = &logrus.TextFormatter{}
		return h
	}
}

func WithDebugLevel() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Level = logrus.DebugLevel
		return h
	}
}

func WithErrorLevel() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Level = logrus.ErrorLevel
		return h
	}
}

func WithWarnLevel() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Level = logrus.WarnLevel
		return h
	}
}

func WithFatalLevel() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Level = logrus.FatalLevel
		return h
	}
}

func WithInfoLevel() Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Level = logrus.InfoLevel
		return h
	}
}

func WithWriter(w io.Writer) Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.Out = w
		return h
	}
}

func WithContext(ctx context.Context) Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.WithContext(ctx)
		return h
	}
}

func WithError(err error) Option {
	return func(h *logrus.Logger) *logrus.Logger {
		h.WithError(err)
		return h
	}
}
