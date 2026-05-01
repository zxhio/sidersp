package config

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Dataplane    DataplaneConfig    `yaml:"dataplane"`
	Egress       EgressConfig       `yaml:"egress"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`
	Console      ConsoleConfig      `yaml:"console"`
	XSK          XSKConfig          `yaml:"xsk"`
	Logging      LoggingConfig      `yaml:"logging"`
}

type ControlPlaneConfig struct {
	RulesPath string `yaml:"rules_path"`
}

type DataplaneConfig struct {
	Interface        string `yaml:"interface"`
	AttachMode       string `yaml:"attach_mode"`
	CombinedChannels int    `yaml:"combined_channels"`
	IngressVerdict   string `yaml:"ingress_verdict"`
}

type ConsoleConfig struct {
	ListenAddr string             `yaml:"listen_addr"`
	Stats      ConsoleStatsConfig `yaml:"stats"`
}

type EgressConfig struct {
	Interface      string `yaml:"interface"`
	VLANMode       string `yaml:"vlan_mode"`
	FailureVerdict string `yaml:"failure_verdict"`
}

type XSKConfig struct {
	Runtime XSKRuntimeConfig `yaml:"runtime"`
}

type XSKRuntimeConfig struct {
	Enabled          bool        `yaml:"enabled"`
	Queues           []int       `yaml:"queues"`
	ResultBufferSize int         `yaml:"result_buffer_size"`
	AFXDP            AFXDPConfig `yaml:"afxdp"`
}

type AFXDPConfig struct {
	FrameSize          uint32 `yaml:"frame_size"`
	FrameCount         uint32 `yaml:"frame_count"`
	FillRingSize       uint32 `yaml:"fill_ring_size"`
	CompletionRingSize uint32 `yaml:"completion_ring_size"`
	RXRingSize         uint32 `yaml:"rx_ring_size"`
	TXRingSize         uint32 `yaml:"tx_ring_size"`
	TXFrameReserve     uint32 `yaml:"tx_frame_reserve"`
}

type LoggingConfig struct {
	App   LogChannelConfig `yaml:"app"`
	Stats LogChannelConfig `yaml:"stats"`
	Event LogChannelConfig `yaml:"event"`
}

type LogChannelConfig struct {
	Level      string `yaml:"level"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   *bool  `yaml:"compress"`
}

type ConsoleStatsConfig struct {
	CollectInterval string `yaml:"collect_interval"`
	Retention       string `yaml:"retention"`
}

type ParsedConsoleStatsConfig struct {
	CollectInterval time.Duration
	Retention       time.Duration
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
	c.Dataplane.applyDefaults()
	c.Console.applyDefaults()
	c.Logging.applyDefaults()
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Dataplane.Interface) == "" {
		return fmt.Errorf("dataplane.interface is required")
	}
	if err := validateAttachMode(c.Dataplane.AttachMode); err != nil {
		return err
	}
	if err := c.Dataplane.validate(); err != nil {
		return err
	}
	if err := c.Egress.validate(); err != nil {
		return fmt.Errorf("egress: %w", err)
	}
	if strings.TrimSpace(c.ControlPlane.RulesPath) == "" {
		return fmt.Errorf("controlplane.rules_path is required")
	}
	if strings.TrimSpace(c.Console.ListenAddr) == "" {
		return fmt.Errorf("console.listen_addr is required")
	}
	if _, err := c.Console.ParsedStats(); err != nil {
		return fmt.Errorf("console.stats: %w", err)
	}
	if err := c.XSK.validate(); err != nil {
		return fmt.Errorf("xsk: %w", err)
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

func (c *DataplaneConfig) applyDefaults() {
	if strings.TrimSpace(c.IngressVerdict) == "" {
		c.IngressVerdict = "pass"
	}
}

func (c *ConsoleConfig) applyDefaults() {
	if strings.TrimSpace(c.Stats.CollectInterval) == "" {
		c.Stats.CollectInterval = "10s"
	}
	if strings.TrimSpace(c.Stats.Retention) == "" {
		c.Stats.Retention = "30d"
	}
}

func (c DataplaneConfig) validate() error {
	if c.CombinedChannels < 0 {
		return fmt.Errorf("dataplane.combined_channels must be >= 0")
	}
	switch normalizeIngressVerdict(c.IngressVerdict) {
	case "pass", "drop":
		return nil
	default:
		return fmt.Errorf("dataplane.ingress_verdict %q is not valid", c.IngressVerdict)
	}
}

func (c XSKConfig) validate() error {
	if err := c.Runtime.validate(); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	return nil
}

func (c XSKRuntimeConfig) validate() error {
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
	return nil
}

func (c EgressConfig) validate() error {
	switch normalizeVLANMode(c.VLANMode) {
	case "preserve", "access":
	default:
		return fmt.Errorf("vlan_mode %q is not valid", c.VLANMode)
	}
	switch normalizeFailureVerdict(c.FailureVerdict) {
	case "pass", "drop":
	default:
		return fmt.Errorf("failure_verdict %q is not valid", c.FailureVerdict)
	}
	return nil
}

func (c *LoggingConfig) applyDefaults() {
	c.App.applyDefaults("app", true)
	c.Stats = c.resolveChannel(c.Stats, "stats", c.App)
	c.Event = c.resolveChannel(c.Event, "event", c.App)
}

func (c LoggingConfig) validate() error {
	if err := c.App.validate("app"); err != nil {
		return err
	}
	if err := c.Stats.validate("stats"); err != nil {
		return err
	}
	if err := c.Event.validate("event"); err != nil {
		return err
	}
	return nil
}

func (c *LogChannelConfig) applyDefaults(channel string, fillDefaultPath bool) {
	if strings.TrimSpace(c.Level) == "" {
		c.Level = "info"
	}
	if fillDefaultPath && strings.TrimSpace(c.FilePath) == "" {
		c.FilePath = defaultLogFilePath(channel)
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
	if c.Compress == nil {
		c.Compress = boolPtr(true)
	}
}

func (c LogChannelConfig) validate(channel string) error {
	if _, err := logrus.ParseLevel(c.Level); err != nil {
		return fmt.Errorf("%s.level %q is not valid", channel, c.Level)
	}
	if strings.TrimSpace(c.FilePath) == "" {
		return fmt.Errorf("%s.file_path is required", channel)
	}
	if c.MaxSizeMB < 0 {
		return fmt.Errorf("%s.max_size_mb must be >= 0", channel)
	}
	if c.MaxBackups < 0 {
		return fmt.Errorf("%s.max_backups must be >= 0", channel)
	}
	if c.MaxAgeDays < 0 {
		return fmt.Errorf("%s.max_age_days must be >= 0", channel)
	}
	return nil
}

func (c LogChannelConfig) CompressEnabled() bool {
	return c.Compress != nil && *c.Compress
}

func (c LogChannelConfig) hasAnyConfig() bool {
	return strings.TrimSpace(c.Level) != "" ||
		strings.TrimSpace(c.FilePath) != "" ||
		c.MaxSizeMB != 0 ||
		c.MaxBackups != 0 ||
		c.MaxAgeDays != 0 ||
		c.Compress != nil
}

func (c *LoggingConfig) resolveChannel(channel LogChannelConfig, name string, fallback LogChannelConfig) LogChannelConfig {
	if !channel.hasAnyConfig() {
		return cloneLogChannelConfig(fallback)
	}
	channel.applyDefaults(name, true)
	return channel
}

func defaultLogFilePath(channel string) string {
	switch channel {
	case "stats":
		return "/var/log/sidersp/sidersp.stats.log"
	case "event":
		return "/var/log/sidersp/sidersp.event.log"
	default:
		return "/var/log/sidersp/sidersp.log"
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func cloneLogChannelConfig(src LogChannelConfig) LogChannelConfig {
	out := src
	if src.Compress != nil {
		out.Compress = boolPtr(*src.Compress)
	}
	return out
}

func (c ConsoleConfig) ParsedStats() (ParsedConsoleStatsConfig, error) {
	collectIntervalRaw := strings.TrimSpace(c.Stats.CollectInterval)
	if collectIntervalRaw == "" {
		collectIntervalRaw = "10s"
	}
	collectInterval, err := parseConsoleDuration(collectIntervalRaw)
	if err != nil {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("collect_interval: %w", err)
	}
	if collectInterval <= 0 {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("collect_interval must be > 0")
	}
	if collectInterval > 10*time.Minute {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("collect_interval must be <= 10m")
	}

	retentionRaw := strings.TrimSpace(c.Stats.Retention)
	if retentionRaw == "" {
		retentionRaw = "30d"
	}
	retention, err := parseConsoleDuration(retentionRaw)
	if err != nil {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("retention: %w", err)
	}
	if retention <= 0 {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("retention must be > 0")
	}
	if retention < 10*time.Minute {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("retention must be >= 10m")
	}
	if retention < collectInterval {
		return ParsedConsoleStatsConfig{}, fmt.Errorf("retention must be >= collect_interval")
	}

	return ParsedConsoleStatsConfig{
		CollectInterval: collectInterval,
		Retention:       retention,
	}, nil
}

func parseConsoleDuration(raw string) (time.Duration, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return 0, fmt.Errorf("duration is required")
	}
	if strings.HasSuffix(value, "d") {
		daysRaw := strings.TrimSpace(strings.TrimSuffix(value, "d"))
		days, err := strconv.ParseInt(daysRaw, 10, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", raw)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	dur, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	return dur, nil
}

func normalizeIngressVerdict(raw string) string {
	verdict := strings.ToLower(strings.TrimSpace(raw))
	if verdict == "" {
		return "pass"
	}
	return verdict
}

func normalizeVLANMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		return "preserve"
	}
	return mode
}

func normalizeFailureVerdict(raw string) string {
	verdict := strings.ToLower(strings.TrimSpace(raw))
	if verdict == "" {
		return "pass"
	}
	return verdict
}
