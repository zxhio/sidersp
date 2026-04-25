package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
)

func TestManagerWritesEachChannelToOwnFile(t *testing.T) {
	t.Parallel()

	manager, paths := newTestManager(t)
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	manager.App().Info("app-only-message")
	manager.Stats().Info("stats-only-message")
	manager.Event().Info("event-only-message")

	appData := readLogFile(t, paths[ChannelApp])
	statsData := readLogFile(t, paths[ChannelStats])
	eventData := readLogFile(t, paths[ChannelEvent])

	if !strings.Contains(appData, "app-only-message") || strings.Contains(appData, "stats-only-message") || strings.Contains(appData, "event-only-message") {
		t.Fatalf("app log = %q, want only app message", appData)
	}
	if !strings.Contains(statsData, "stats-only-message") || strings.Contains(statsData, "app-only-message") || strings.Contains(statsData, "event-only-message") {
		t.Fatalf("stats log = %q, want only stats message", statsData)
	}
	if !strings.Contains(eventData, "event-only-message") || strings.Contains(eventData, "app-only-message") || strings.Contains(eventData, "stats-only-message") {
		t.Fatalf("event log = %q, want only event message", eventData)
	}
}

func TestManagerSetChannelLevelOnlyAffectsTargetChannel(t *testing.T) {
	t.Parallel()

	manager, _ := newTestManager(t)
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	level, err := manager.SetChannelLevel(ChannelEvent, "debug")
	if err != nil {
		t.Fatalf("SetChannelLevel() error = %v", err)
	}
	if level != "debug" {
		t.Fatalf("SetChannelLevel() level = %q, want debug", level)
	}

	levels := manager.Levels()
	if levels.App != "info" || levels.Stats != "info" || levels.Event != "debug" {
		t.Fatalf("Levels() = %+v, want app=info stats=info event=debug", levels)
	}
	if manager.App().IsLevelEnabled(logrus.DebugLevel) {
		t.Fatal("App() debug enabled = true, want false")
	}
	if !manager.Event().IsLevelEnabled(logrus.DebugLevel) {
		t.Fatal("Event() debug enabled = false, want true")
	}
}

func TestManagerSetLevelCompatibilityUsesAppChannel(t *testing.T) {
	t.Parallel()

	manager, _ := newTestManager(t)
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	level, err := manager.SetLevel("warning")
	if err != nil {
		t.Fatalf("SetLevel() error = %v", err)
	}
	if level != "warn" {
		t.Fatalf("SetLevel() level = %q, want warn", level)
	}

	levels := manager.Levels()
	if levels.App != "warn" || levels.Stats != "info" || levels.Event != "info" {
		t.Fatalf("Levels() = %+v, want app=warn stats=info event=info", levels)
	}
}

func TestManagerSupportsSharedLogFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sharedPath := filepath.Join(dir, "sidersp.log")
	manager, err := NewManager(config.LoggingConfig{
		App: config.LogChannelConfig{
			Level:      "info",
			FilePath:   sharedPath,
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
		Stats: config.LogChannelConfig{
			Level:      "debug",
			FilePath:   sharedPath,
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
		Event: config.LogChannelConfig{
			Level:      "warn",
			FilePath:   sharedPath,
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	manager.App().Info("shared-app-message")
	manager.Stats().Info("shared-stats-message")
	manager.Event().Warn("shared-event-message")

	data := readLogFile(t, sharedPath)
	if !strings.Contains(data, "shared-app-message") || !strings.Contains(data, "shared-stats-message") || !strings.Contains(data, "shared-event-message") {
		t.Fatalf("shared log = %q, want all channel messages", data)
	}
}

func TestManagerRejectsConflictingSharedWriterConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sharedPath := filepath.Join(dir, "sidersp.log")
	_, err := NewManager(config.LoggingConfig{
		App: config.LogChannelConfig{
			Level:      "info",
			FilePath:   sharedPath,
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
		Stats: config.LogChannelConfig{
			Level:      "info",
			FilePath:   sharedPath,
			MaxSizeMB:  20,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
		Event: config.LogChannelConfig{
			Level:      "info",
			FilePath:   filepath.Join(dir, "sidersp.event.log"),
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
	})
	if err == nil {
		t.Fatal("NewManager() error = nil, want shared-writer validation error")
	}
	if !strings.Contains(err.Error(), "conflicting rotation settings") {
		t.Fatalf("NewManager() error = %q, want conflicting rotation settings", err)
	}
}

func newTestManager(t testing.TB) (*Manager, map[string]string) {
	t.Helper()

	dir := t.TempDir()
	paths := map[string]string{
		ChannelApp:   filepath.Join(dir, "sidersp.log"),
		ChannelStats: filepath.Join(dir, "sidersp.stats.log"),
		ChannelEvent: filepath.Join(dir, "sidersp.event.log"),
	}

	manager, err := NewManager(config.LoggingConfig{
		App: config.LogChannelConfig{
			Level:      "info",
			FilePath:   paths[ChannelApp],
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
		Stats: config.LogChannelConfig{
			Level:      "info",
			FilePath:   paths[ChannelStats],
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
		Event: config.LogChannelConfig{
			Level:      "info",
			FilePath:   paths[ChannelEvent],
			MaxSizeMB:  10,
			MaxBackups: 2,
			MaxAgeDays: 3,
			Compress:   boolRef(false),
		},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager, paths
}

func readLogFile(t testing.TB, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file %s: %v", path, err)
	}
	return string(data)
}

func boolRef(value bool) *bool {
	return &value
}
