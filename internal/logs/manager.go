package logs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"sidersp/internal/config"
)

const (
	ChannelApp   = "app"
	ChannelStats = "stats"
	ChannelEvent = "event"
)

type Levels struct {
	App   string `json:"app"`
	Stats string `json:"stats"`
	Event string `json:"event"`
}

type Manager struct {
	channels map[string]*channelLogger
}

type channelLogger struct {
	logger *logrus.Logger
	file   *lumberjack.Logger
}

var (
	defaultManager atomic.Pointer[Manager]
	fallbackOnce   sync.Once
	fallbackSet    fallbackLoggers
)

type fallbackLoggers struct {
	app   *logrus.Logger
	stats *logrus.Logger
	event *logrus.Logger
}

func NewManager(cfg config.LoggingConfig) (*Manager, error) {
	channels := make(map[string]*channelLogger, 3)
	writers := make(map[string]*lumberjack.Logger, 3)
	writerConfigs := make(map[string]config.LogChannelConfig, 3)
	for _, item := range []struct {
		name string
		cfg  config.LogChannelConfig
	}{
		{name: ChannelApp, cfg: cfg.App},
		{name: ChannelStats, cfg: cfg.Stats},
		{name: ChannelEvent, cfg: cfg.Event},
	} {
		logger, err := newChannelLogger(item.cfg, writers, writerConfigs)
		if err != nil {
			closeChannelLoggers(channels)
			return nil, fmt.Errorf("%s logger: %w", item.name, err)
		}
		channels[item.name] = logger
	}

	return &Manager{channels: channels}, nil
}

func App() *logrus.Logger {
	if manager := currentDefaultManager(); manager != nil {
		return manager.App()
	}
	return fallback().app
}

func Stats() *logrus.Logger {
	if manager := currentDefaultManager(); manager != nil {
		return manager.Stats()
	}
	return fallback().stats
}

func Event() *logrus.Logger {
	if manager := currentDefaultManager(); manager != nil {
		return manager.Event()
	}
	return fallback().event
}

func SetDefaultManager(manager *Manager) {
	defaultManager.Store(manager)
}

func ResetDefaultManager() {
	defaultManager.Store(nil)
}

func (m *Manager) App() *logrus.Logger {
	return m.logger(ChannelApp)
}

func (m *Manager) Stats() *logrus.Logger {
	return m.logger(ChannelStats)
}

func (m *Manager) Event() *logrus.Logger {
	return m.logger(ChannelEvent)
}

func (m *Manager) Level() string {
	return m.channelLevel(ChannelApp)
}

func (m *Manager) Levels() Levels {
	return Levels{
		App:   m.channelLevel(ChannelApp),
		Stats: m.channelLevel(ChannelStats),
		Event: m.channelLevel(ChannelEvent),
	}
}

func (m *Manager) SetLevel(raw string) (string, error) {
	return m.SetChannelLevel(ChannelApp, raw)
}

func (m *Manager) SetLevels(levels Levels) (Levels, error) {
	parsed := make(map[string]logrus.Level, 3)
	for _, item := range []struct {
		channel string
		level   string
	}{
		{channel: ChannelApp, level: levels.App},
		{channel: ChannelStats, level: levels.Stats},
		{channel: ChannelEvent, level: levels.Event},
	} {
		level, err := parseLevel(item.level)
		if err != nil {
			return Levels{}, fmt.Errorf("%s: %w", item.channel, err)
		}
		parsed[item.channel] = level
	}

	for channel, level := range parsed {
		m.logger(channel).SetLevel(level)
	}

	return m.Levels(), nil
}

func (m *Manager) SetChannelLevel(channel string, raw string) (string, error) {
	level, err := parseLevel(raw)
	if err != nil {
		return "", err
	}

	logger := m.logger(channel)
	if logger == nil {
		return "", fmt.Errorf("logging channel %q is not valid", channel)
	}
	logger.SetLevel(level)
	return formatLevel(level), nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}

	var firstErr error
	seen := make(map[*lumberjack.Logger]struct{}, len(m.channels))
	for _, channel := range []string{ChannelApp, ChannelStats, ChannelEvent} {
		item := m.channels[channel]
		if item == nil || item.file == nil {
			continue
		}
		if _, ok := seen[item.file]; ok {
			continue
		}
		seen[item.file] = struct{}{}
		if err := item.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func newChannelLogger(cfg config.LogChannelConfig, writers map[string]*lumberjack.Logger, writerConfigs map[string]config.LogChannelConfig) (*channelLogger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	filePath := filepath.Clean(cfg.FilePath)
	writer := writers[filePath]
	if writer == nil {
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}

		writer = &lumberjack.Logger{
			Filename:   filePath,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   cfg.CompressEnabled(),
		}
		writers[filePath] = writer
		writerConfigs[filePath] = cfg
	} else if !sameWriterConfig(writerConfigs[filePath], cfg) {
		return nil, fmt.Errorf("shared log file %q has conflicting rotation settings", filePath)
	}

	return &channelLogger{
		logger: newLogger(writer, level),
		file:   writer,
	}, nil
}

func newLogger(out io.Writer, level logrus.Level) *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(out)
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logger.SetLevel(level)
	return logger
}

func parseLevel(raw string) (logrus.Level, error) {
	level, err := logrus.ParseLevel(raw)
	if err != nil {
		return 0, fmt.Errorf("logging level %q is not valid", raw)
	}
	return level, nil
}

func currentDefaultManager() *Manager {
	return defaultManager.Load()
}

func fallback() fallbackLoggers {
	fallbackOnce.Do(func() {
		fallbackSet = fallbackLoggers{
			app:   newLogger(os.Stderr, logrus.InfoLevel),
			stats: newLogger(os.Stderr, logrus.InfoLevel),
			event: newLogger(os.Stderr, logrus.InfoLevel),
		}
	})
	return fallbackSet
}

func (m *Manager) logger(channel string) *logrus.Logger {
	if m == nil {
		return nil
	}

	item := m.channels[channel]
	if item == nil {
		return nil
	}
	return item.logger
}

func (m *Manager) channelLevel(channel string) string {
	logger := m.logger(channel)
	if logger == nil {
		return ""
	}
	return formatLevel(logger.GetLevel())
}

func closeChannelLoggers(channels map[string]*channelLogger) {
	seen := make(map[*lumberjack.Logger]struct{}, len(channels))
	for _, item := range channels {
		if item == nil || item.file == nil {
			continue
		}
		if _, ok := seen[item.file]; ok {
			continue
		}
		seen[item.file] = struct{}{}
		_ = item.file.Close()
	}
}

func sameWriterConfig(a config.LogChannelConfig, b config.LogChannelConfig) bool {
	return a.MaxSizeMB == b.MaxSizeMB &&
		a.MaxBackups == b.MaxBackups &&
		a.MaxAgeDays == b.MaxAgeDays &&
		a.CompressEnabled() == b.CompressEnabled()
}

func formatLevel(level logrus.Level) string {
	if level == logrus.WarnLevel {
		return "warn"
	}
	return level.String()
}
