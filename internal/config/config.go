package config

import (
	"bytes"
	"fmt"
	"net"
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
	Response     ResponseConfig     `yaml:"response"`
	Logging      LoggingConfig      `yaml:"logging"`
}

type ControlPlaneConfig struct {
	RulesPath string `yaml:"rules_path"`
}

type DataplaneConfig struct {
	Interface      string `yaml:"interface"`
	AttachMode     string `yaml:"attach_mode"`
	IngressVerdict string `yaml:"ingress_verdict"`
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

type ResponseConfig struct {
	Runtime ResponseRuntimeConfig `yaml:"runtime"`
	Actions ResponseActionsConfig `yaml:"actions"`
}

type ResponseRuntimeConfig struct {
	Enabled          bool        `yaml:"enabled"`
	Queues           []int       `yaml:"queues"`
	ResultBufferSize int         `yaml:"result_buffer_size"`
	AFXDP            AFXDPConfig `yaml:"afxdp"`
}

type ResponseActionsConfig struct {
	ARPReply  ARPReplyConfig  `yaml:"arp_reply"`
	TCPSynAck TCPSynAckConfig `yaml:"tcp_syn_ack"`
}

type ARPReplyConfig struct {
	HardwareAddr string `yaml:"hardware_addr"`
}

type TCPSynAckConfig struct {
	TCPSeq uint32 `yaml:"tcp_seq"`
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
	Level      string `yaml:"level"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
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

func (c DataplaneConfig) NormalizedIngressVerdict() string {
	verdict := strings.ToLower(strings.TrimSpace(c.IngressVerdict))
	if verdict == "" {
		return "pass"
	}
	return verdict
}

func (c DataplaneConfig) validate() error {
	switch c.NormalizedIngressVerdict() {
	case "pass", "drop":
		return nil
	default:
		return fmt.Errorf("dataplane.ingress_verdict %q is not valid", c.IngressVerdict)
	}
}

func (c EgressConfig) TXPath() string {
	if strings.TrimSpace(c.Interface) == "" {
		return "same-interface"
	}
	return "egress-interface"
}

func (c EgressConfig) NormalizedVLANMode() string {
	mode := strings.ToLower(strings.TrimSpace(c.VLANMode))
	if mode == "" {
		return "preserve"
	}
	return mode
}

func (c EgressConfig) NormalizedFailureVerdict() string {
	verdict := strings.ToLower(strings.TrimSpace(c.FailureVerdict))
	if verdict == "" {
		return "pass"
	}
	return verdict
}

func (c ResponseRuntimeConfig) WorkerQueues() []int {
	if len(c.Queues) == 0 {
		return []int{0}
	}
	return append([]int(nil), c.Queues...)
}

func (c ResponseRuntimeConfig) ResultBufferCapacity() int {
	if c.ResultBufferSize <= 0 {
		return 1024
	}
	return c.ResultBufferSize
}

func (c ResponseConfig) validate() error {
	if err := c.Runtime.validate(); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	if err := c.Actions.validate(); err != nil {
		return fmt.Errorf("actions: %w", err)
	}
	return nil
}

func (c ResponseRuntimeConfig) validate() error {
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

func (c ResponseActionsConfig) validate() error {
	if strings.TrimSpace(c.ARPReply.HardwareAddr) != "" {
		hw, err := net.ParseMAC(c.ARPReply.HardwareAddr)
		if err != nil {
			return fmt.Errorf("hardware_addr: %w", err)
		}
		if len(hw) != 6 {
			return fmt.Errorf("hardware_addr must be a 6-byte ethernet address")
		}
	}
	return nil
}

func (c EgressConfig) validate() error {
	switch c.NormalizedVLANMode() {
	case "preserve", "access":
	default:
		return fmt.Errorf("vlan_mode %q is not valid", c.VLANMode)
	}
	switch c.NormalizedFailureVerdict() {
	case "pass", "drop":
	default:
		return fmt.Errorf("failure_verdict %q is not valid", c.FailureVerdict)
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
