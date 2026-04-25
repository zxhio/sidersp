package dataplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sidersp/internal/config"
	"sidersp/internal/logs"
)

func TestLogMatchedRuleRoutesToEventLog(t *testing.T) {
	manager, paths := newTestLogsManager(t)
	logs.SetDefaultManager(manager)
	t.Cleanup(func() {
		logs.ResetDefaultManager()
		_ = manager.Close()
	})

	runtime := &Runtime{}
	runtime.logMatchedRule(ruleEvent{RuleID: 7})

	appData := readRuntimeLogFile(t, paths[logs.ChannelApp])
	statsData := readRuntimeLogFile(t, paths[logs.ChannelStats])
	eventData := readRuntimeLogFile(t, paths[logs.ChannelEvent])

	if strings.Contains(appData, "Matched rule") {
		t.Fatalf("app log = %q, want no matched rule event", appData)
	}
	if strings.Contains(statsData, "Matched rule") {
		t.Fatalf("stats log = %q, want no matched rule event", statsData)
	}
	if !strings.Contains(eventData, "Matched rule") {
		t.Fatalf("event log = %q, want matched rule event", eventData)
	}
}

func TestLogKernelStatsSnapshotRoutesToStatsLog(t *testing.T) {
	manager, paths := newTestLogsManager(t)
	logs.SetDefaultManager(manager)
	t.Cleanup(func() {
		logs.ResetDefaultManager()
		_ = manager.Close()
	})

	runtime := &Runtime{}
	runtime.logKernelStatsSnapshot(kernelStats{RXPackets: 1})

	appData := readRuntimeLogFile(t, paths[logs.ChannelApp])
	statsData := readRuntimeLogFile(t, paths[logs.ChannelStats])
	eventData := readRuntimeLogFile(t, paths[logs.ChannelEvent])

	if strings.Contains(appData, "Reported kernel stats") {
		t.Fatalf("app log = %q, want no stats snapshot", appData)
	}
	if strings.Contains(eventData, "Reported kernel stats") {
		t.Fatalf("event log = %q, want no stats snapshot", eventData)
	}
	if !strings.Contains(statsData, "Reported kernel stats") {
		t.Fatalf("stats log = %q, want stats snapshot", statsData)
	}
}

func newTestLogsManager(t testing.TB) (*logs.Manager, map[string]string) {
	t.Helper()

	dir := t.TempDir()
	paths := map[string]string{
		logs.ChannelApp:   filepath.Join(dir, "sidersp.log"),
		logs.ChannelStats: filepath.Join(dir, "sidersp.stats.log"),
		logs.ChannelEvent: filepath.Join(dir, "sidersp.event.log"),
	}

	manager, err := logs.NewManager(config.LoggingConfig{
		App: config.LogChannelConfig{
			Level:      "info",
			FilePath:   paths[logs.ChannelApp],
			MaxSizeMB:  10,
			MaxBackups: 1,
			MaxAgeDays: 1,
			Compress:   boolValue(false),
		},
		Stats: config.LogChannelConfig{
			Level:      "info",
			FilePath:   paths[logs.ChannelStats],
			MaxSizeMB:  10,
			MaxBackups: 1,
			MaxAgeDays: 1,
			Compress:   boolValue(false),
		},
		Event: config.LogChannelConfig{
			Level:      "info",
			FilePath:   paths[logs.ChannelEvent],
			MaxSizeMB:  10,
			MaxBackups: 1,
			MaxAgeDays: 1,
			Compress:   boolValue(false),
		},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	return manager, paths
}

func readRuntimeLogFile(t testing.TB, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file %s: %v", path, err)
	}
	return string(data)
}

func boolValue(value bool) *bool {
	return &value
}
