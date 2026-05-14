package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadMinimalConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

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
	stats, err := cfg.Console.ParsedStats()
	if err != nil {
		t.Fatalf("ParsedStats() error = %v", err)
	}
	if stats.CollectInterval != 10*time.Second || stats.Retention != 30*24*time.Hour {
		t.Fatalf("default console stats = %+v, want collect_interval=10s retention=30d", stats)
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

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	return path
}
