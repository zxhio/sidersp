package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Dataplane    DataplaneConfig    `yaml:"dataplane"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`
	Console      ConsoleConfig      `yaml:"console"`
}

type ControlPlaneConfig struct {
	RulesPath string `yaml:"rules_path"`
}

type DataplaneConfig struct {
	Interface  string `yaml:"interface"`
	AttachMode string `yaml:"attach_mode"`
}

type ConsoleConfig struct {
	ListenAddr   string             `yaml:"listen_addr"`
	StatsHistory StatsHistoryConfig `yaml:"stats_history"`
}

type StatsHistoryConfig struct {
	Windows []StatsHistoryWindowConfig `yaml:"windows"`
}

type StatsHistoryWindowConfig struct {
	Name   string `yaml:"name"`
	Window string `yaml:"window"`
	Step   string `yaml:"step"`
	Limit  int    `yaml:"limit"`
}

type ParsedStatsHistoryWindow struct {
	Name   string
	Window time.Duration
	Step   time.Duration
	Limit  int
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
func (c Config) validate() error {
	if strings.TrimSpace(c.Dataplane.Interface) == "" {
		return fmt.Errorf("dataplane.interface is required")
	}
	if strings.TrimSpace(c.ControlPlane.RulesPath) == "" {
		return fmt.Errorf("controlplane.rules_path is required")
	}
	if strings.TrimSpace(c.Console.ListenAddr) == "" {
		return fmt.Errorf("console.listen_addr is required")
	}
	if _, err := c.Console.ParsedStatsHistoryWindows(); err != nil {
		return fmt.Errorf("console.stats_history: %w", err)
	}

	return nil
}

func DefaultStatsHistoryWindows() []StatsHistoryWindowConfig {
	return []StatsHistoryWindowConfig{
		{Name: "10min", Window: "10m", Step: "10s", Limit: 60},
		{Name: "1d", Window: "24h", Step: "15m", Limit: 96},
		{Name: "30d", Window: "720h", Step: "8h", Limit: 90},
	}
}

func (c ConsoleConfig) ParsedStatsHistoryWindows() ([]ParsedStatsHistoryWindow, error) {
	items := c.StatsHistory.Windows
	if len(items) == 0 {
		items = DefaultStatsHistoryWindows()
	}

	parsed := make([]ParsedStatsHistoryWindow, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, fmt.Errorf("window name is required")
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate window name %q", name)
		}
		seen[name] = struct{}{}

		window, err := time.ParseDuration(strings.TrimSpace(item.Window))
		if err != nil {
			return nil, fmt.Errorf("window %q duration: %w", name, err)
		}
		if window <= 0 {
			return nil, fmt.Errorf("window %q duration must be > 0", name)
		}

		step, err := time.ParseDuration(strings.TrimSpace(item.Step))
		if err != nil {
			return nil, fmt.Errorf("window %q step: %w", name, err)
		}
		if step <= 0 {
			return nil, fmt.Errorf("window %q step must be > 0", name)
		}
		if step > window {
			return nil, fmt.Errorf("window %q step must be <= window", name)
		}

		limit := item.Limit
		if limit <= 0 {
			limit = int(window / step)
			if limit <= 0 {
				limit = 1
			}
		}

		parsed = append(parsed, ParsedStatsHistoryWindow{
			Name:   name,
			Window: window,
			Step:   step,
			Limit:  limit,
		})
	}

	return parsed, nil
}
