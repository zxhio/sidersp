package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0
  attach_mode: driver

console:
  listen_addr: 127.0.0.1:8080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ControlPlane.RulesPath != "configs/rules.example.yaml" {
		t.Fatalf("ControlPlane.RulesPath = %q, want %q", cfg.ControlPlane.RulesPath, "configs/rules.example.yaml")
	}

	if cfg.Dataplane.Interface != "eth0" {
		t.Fatalf("Dataplane.Interface = %q, want %q", cfg.Dataplane.Interface, "eth0")
	}
	windows, err := cfg.Console.ParsedStatsHistoryWindows()
	if err != nil {
		t.Fatalf("ParsedStatsHistoryWindows() error = %v", err)
	}
	if len(windows) != 3 {
		t.Fatalf("len(windows) = %d, want 3", len(windows))
	}
	if windows[1].Step != 15*time.Minute || windows[2].Step != 8*time.Hour {
		t.Fatalf("default windows = %+v, want 1d=15m 30d=8h", windows)
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml
  extra: nope

dataplane:
  interface: eth0

console:
  listen_addr: 127.0.0.1:8080
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}

	if !strings.Contains(err.Error(), `field extra not found`) {
		t.Fatalf("Load() error = %q, want unknown key error", err)
	}
}

func TestLoadRejectsMissingRequiredField(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path:

dataplane:
  interface: eth0

console:
  listen_addr: 127.0.0.1:8080
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want required field error")
	}

	if !strings.Contains(err.Error(), "controlplane.rules_path is required") {
		t.Fatalf("Load() error = %q, want required field error", err)
	}
}

func TestLoadRejectsMissingDataplaneInterface(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface:

console:
  listen_addr: 127.0.0.1:8080
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want required field error")
	}

	if !strings.Contains(err.Error(), "dataplane.interface is required") {
		t.Fatalf("Load() error = %q, want dataplane interface required error", err)
	}
}

func TestLoadStatsHistoryConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

console:
  listen_addr: 127.0.0.1:8080
  stats_history:
    windows:
      - name: recent
        window: 30m
        step: 1m
        limit: 30
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	windows, err := cfg.Console.ParsedStatsHistoryWindows()
	if err != nil {
		t.Fatalf("ParsedStatsHistoryWindows() error = %v", err)
	}
	if len(windows) != 1 {
		t.Fatalf("len(windows) = %d, want 1", len(windows))
	}
	if windows[0].Name != "recent" || windows[0].Window != 30*time.Minute || windows[0].Step != time.Minute || windows[0].Limit != 30 {
		t.Fatalf("window = %+v, want name=recent window=30m step=1m limit=30", windows[0])
	}
}

func TestLoadRejectsInvalidStatsHistoryWindow(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

console:
  listen_addr: 127.0.0.1:8080
  stats_history:
    windows:
      - name: bad
        window: bad
        step: 10s
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want stats history window validation error")
	}

	if !strings.Contains(err.Error(), "console.stats_history") {
		t.Fatalf("Load() error = %q, want stats history window error", err)
	}
}

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	return path
}
