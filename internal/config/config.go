package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Dataplane    DataplaneConfig    `yaml:"dataplane"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`
	Console      ConsoleConfig      `yaml:"console"`
	Response     ResponseConfig     `yaml:"response"`
	Logging      LoggingConfig      `yaml:"logging"`
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

type ResponseConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Queues           []int  `yaml:"queues"`
	ResultBufferSize int    `yaml:"result_buffer_size"`
	HardwareAddr     string `yaml:"hardware_addr"`
	TCPSeq           uint32 `yaml:"tcp_seq"`

	// AF_XDP socket settings.
	FrameSize          uint32 `yaml:"frame_size"`
	FrameCount         uint32 `yaml:"frame_count"`
	FillRingSize       uint32 `yaml:"fill_ring_size"`
	CompletionRingSize uint32 `yaml:"completion_ring_size"`
	RXRingSize         uint32 `yaml:"rx_ring_size"`
	TXRingSize         uint32 `yaml:"tx_ring_size"`
	TXFrameReserve     uint32 `yaml:"tx_frame_reserve"`
}

type LoggingConfig struct {
	Level      string `yaml:"level"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
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

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	c.Logging.applyDefaults()
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Dataplane.Interface) == "" {
		return fmt.Errorf("dataplane.interface is required")
	}
	if err := validateAttachMode(c.Dataplane.AttachMode); err != nil {
		return err
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
	if err := c.Response.validate(); err != nil {
		return fmt.Errorf("response: %w", err)
	}
	if err := c.Logging.validate(); err != nil {
		return fmt.Errorf("logging: %w", err)
	}

	return nil
}

func validateAttachMode(raw string) error {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "driver", "drv", "native", "generic", "skb", "offload", "hw":
		return nil
	default:
		return fmt.Errorf("dataplane.attach_mode %q is not valid", raw)
	}
}

func (c ResponseConfig) WorkerQueues() []int {
	if len(c.Queues) == 0 {
		return []int{0}
	}
	return append([]int(nil), c.Queues...)
}

func (c ResponseConfig) ResultBufferCapacity() int {
	if c.ResultBufferSize <= 0 {
		return 1024
	}
	return c.ResultBufferSize
}

func (c ResponseConfig) validate() error {
	if c.ResultBufferSize < 0 {
		return fmt.Errorf("result_buffer_size must be >= 0")
	}
	seenQueues := make(map[int]struct{}, len(c.Queues))
	for _, queue := range c.Queues {
		if queue < 0 {
			return fmt.Errorf("queue %d out of range", queue)
		}
		if _, ok := seenQueues[queue]; ok {
			return fmt.Errorf("duplicate queue %d", queue)
		}
		seenQueues[queue] = struct{}{}
	}
	if strings.TrimSpace(c.HardwareAddr) != "" {
		hw, err := net.ParseMAC(c.HardwareAddr)
		if err != nil {
			return fmt.Errorf("hardware_addr: %w", err)
		}
		if len(hw) != 6 {
			return fmt.Errorf("hardware_addr must be a 6-byte ethernet address")
		}
	}
	return nil
}

func (c *LoggingConfig) applyDefaults() {
	if strings.TrimSpace(c.Level) == "" {
		c.Level = "info"
	}
	if strings.TrimSpace(c.FilePath) == "" {
		c.FilePath = "/var/log/sidersp/sidersp.log"
	}
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = 100
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = 7
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = 30
	}
}

func (c LoggingConfig) validate() error {
	if _, err := logrus.ParseLevel(c.Level); err != nil {
		return fmt.Errorf("level %q is not valid", c.Level)
	}
	if strings.TrimSpace(c.FilePath) == "" {
		return fmt.Errorf("file_path is required")
	}
	if c.MaxSizeMB < 0 {
		return fmt.Errorf("max_size_mb must be >= 0")
	}
	if c.MaxBackups < 0 {
		return fmt.Errorf("max_backups must be >= 0")
	}
	if c.MaxAgeDays < 0 {
		return fmt.Errorf("max_age_days must be >= 0")
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
