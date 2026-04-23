package logging

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"sidersp/internal/config"
)

type Manager struct {
	file *lumberjack.Logger
}

func NewManager(cfg config.LoggingConfig) (*Manager, error) {
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("logging level %q is not valid", cfg.Level)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	writer := &lumberjack.Logger{
		Filename:   cfg.FilePath,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}

	logrus.SetOutput(writer)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logrus.SetLevel(level)

	return &Manager{
		file: writer,
	}, nil
}

func (m *Manager) Level() string {
	return formatLevel(logrus.GetLevel())
}

func (m *Manager) SetLevel(raw string) (string, error) {
	level, err := logrus.ParseLevel(raw)
	if err != nil {
		return "", fmt.Errorf("logging level %q is not valid", raw)
	}

	logrus.SetLevel(level)
	return formatLevel(level), nil
}

func (m *Manager) Close() error {
	return m.file.Close()
}

func formatLevel(level logrus.Level) string {
	if level == logrus.WarnLevel {
		return "warn"
	}
	return level.String()
}
