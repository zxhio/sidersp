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
	if got := normalizeIngressVerdict(cfg.Dataplane.IngressVerdict); got != "pass" {
		t.Fatalf("normalizeIngressVerdict(%q) = %q, want pass", cfg.Dataplane.IngressVerdict, got)
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

func TestLoadRejectsInvalidAttachMode(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0
  attach_mode: invalid

console:
  listen_addr: 127.0.0.1:8080
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want attach mode validation error")
	}

	if !strings.Contains(err.Error(), `dataplane.attach_mode "invalid" is not valid`) {
		t.Fatalf("Load() error = %q, want attach mode validation error", err)
	}
}

func TestLoadDataplaneIngressVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		verdict string
		want    string
	}{
		{name: "pass", verdict: "pass", want: "pass"},
		{name: "drop", verdict: "drop", want: "drop"},
		{name: "uppercase pass", verdict: "PASS", want: "pass"},
		{name: "spaced drop", verdict: " drop ", want: "drop"},
		{name: "default pass", verdict: "", want: "pass"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0
`+dataplaneIngressVerdictLine(tc.verdict)+`
console:
  listen_addr: 127.0.0.1:8080
`)

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := normalizeIngressVerdict(cfg.Dataplane.IngressVerdict); got != tc.want {
				t.Fatalf("normalizeIngressVerdict(%q) = %q, want %q", cfg.Dataplane.IngressVerdict, got, tc.want)
			}
		})
	}
}

func TestLoadConsoleStatsConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

console:
  listen_addr: 127.0.0.1:8080
  stats:
    collect_interval: 15s
    retention: 7d
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	stats, err := cfg.Console.ParsedStats()
	if err != nil {
		t.Fatalf("ParsedStats() error = %v", err)
	}
	if stats.CollectInterval != 15*time.Second || stats.Retention != 7*24*time.Hour {
		t.Fatalf("console stats = %+v, want collect_interval=15s retention=7d", stats)
	}
}

func TestLoadResponseConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

egress:
  interface: eth1
  vlan_mode: access
  failure_verdict: drop

response:
  runtime:
    enabled: true
    queues: [0, 1]
    result_buffer_size: 2048
    afxdp:
      frame_size: 4096
      tx_frame_reserve: 256
  actions:
    arp_reply:
      hardware_addr: 02:aa:bb:cc:dd:ee
    tcp_syn_ack:
      tcp_seq: 1000

console:
  listen_addr: 127.0.0.1:8080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Response.Runtime.Enabled {
		t.Fatal("Response.Runtime.Enabled = false, want true")
	}
	if got := cfg.Response.Runtime.Queues; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("Response.Runtime.Queues = %+v, want [0 1]", got)
	}
	if cfg.Response.Runtime.ResultBufferSize != 2048 {
		t.Fatalf("Response.Runtime.ResultBufferSize = %d, want 2048", cfg.Response.Runtime.ResultBufferSize)
	}
	if cfg.Response.Actions.ARPReply.HardwareAddr != "02:aa:bb:cc:dd:ee" || cfg.Response.Actions.TCPSynAck.TCPSeq != 1000 {
		t.Fatalf("Response = %+v, want arp_reply/tcp_syn_ack populated", cfg.Response)
	}
	if cfg.Egress.Interface != "eth1" ||
		normalizeVLANMode(cfg.Egress.VLANMode) != "access" ||
		normalizeFailureVerdict(cfg.Egress.FailureVerdict) != "drop" {
		t.Fatalf("Egress = %+v, want egress-interface/access/drop", cfg.Egress)
	}
	if cfg.Response.Runtime.AFXDP.FrameSize != 4096 || cfg.Response.Runtime.AFXDP.TXFrameReserve != 256 {
		t.Fatalf("AFXDP = %+v, want frame_size=4096 tx_frame_reserve=256", cfg.Response.Runtime.AFXDP)
	}
}

func TestLoadLoggingConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

logging:
  app:
    level: debug
    file_path: /tmp/sidersp.log
    max_size_mb: 10
    max_backups: 2
    max_age_days: 3
    compress: false
  stats:
    level: info
    file_path: /tmp/sidersp.stats.log
    max_size_mb: 11
    max_backups: 4
    max_age_days: 5
    compress: true
  event:
    level: warn
    file_path: /tmp/sidersp.event.log
    max_size_mb: 12
    max_backups: 6
    max_age_days: 7
    compress: true

console:
  listen_addr: 127.0.0.1:8080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.App.Level != "debug" || cfg.Logging.App.FilePath != "/tmp/sidersp.log" || cfg.Logging.App.CompressEnabled() {
		t.Fatalf("app logging = %+v, want debug /tmp/sidersp.log compress=false", cfg.Logging.App)
	}
	if cfg.Logging.Stats.Level != "info" || cfg.Logging.Stats.FilePath != "/tmp/sidersp.stats.log" || !cfg.Logging.Stats.CompressEnabled() {
		t.Fatalf("stats logging = %+v, want info /tmp/sidersp.stats.log compress=true", cfg.Logging.Stats)
	}
	if cfg.Logging.Event.Level != "warn" || cfg.Logging.Event.FilePath != "/tmp/sidersp.event.log" || !cfg.Logging.Event.CompressEnabled() {
		t.Fatalf("event logging = %+v, want warn /tmp/sidersp.event.log compress=true", cfg.Logging.Event)
	}
}

func TestLoadRejectsLegacyLoggingConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

logging:
  level: debug
  file_path: /tmp/legacy.log
  max_size_mb: 55
  max_backups: 6
  max_age_days: 9
  compress: false

console:
  listen_addr: 127.0.0.1:8080
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want unknown key error")
	}
	if !strings.Contains(err.Error(), `field level not found`) {
		t.Fatalf("Load() error = %q, want legacy logging key rejection", err)
	}
}

func TestLoadLoggingChannelsFallbackToAppWhenOmitted(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

logging:
  app:
    level: warn
    file_path: /tmp/sidersp.log
    max_size_mb: 90
    max_backups: 8
    max_age_days: 7
    compress: false

console:
  listen_addr: 127.0.0.1:8080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.Stats.Level != "warn" || cfg.Logging.Stats.FilePath != "/tmp/sidersp.log" || cfg.Logging.Stats.MaxSizeMB != 90 || cfg.Logging.Stats.CompressEnabled() {
		t.Fatalf("stats logging = %+v, want app fallback", cfg.Logging.Stats)
	}
	if cfg.Logging.Event.Level != "warn" || cfg.Logging.Event.FilePath != "/tmp/sidersp.log" || cfg.Logging.Event.MaxBackups != 8 || cfg.Logging.Event.CompressEnabled() {
		t.Fatalf("event logging = %+v, want app fallback", cfg.Logging.Event)
	}
}

func TestLoadLoggingChannelUsesOwnDefaultsWhenConfigured(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

logging:
  app:
    level: warn
    file_path: /tmp/sidersp.log
    max_size_mb: 90
    max_backups: 8
    max_age_days: 7
    compress: false
  stats:
    level: info
  event:
    file_path: /tmp/sidersp.event.log

console:
  listen_addr: 127.0.0.1:8080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Logging.Stats.Level != "info" || cfg.Logging.Stats.FilePath != "/var/log/sidersp/sidersp.stats.log" || cfg.Logging.Stats.MaxSizeMB != 100 || !cfg.Logging.Stats.CompressEnabled() {
		t.Fatalf("stats logging = %+v, want own defaults", cfg.Logging.Stats)
	}
	if cfg.Logging.Event.Level != "info" || cfg.Logging.Event.FilePath != "/tmp/sidersp.event.log" || cfg.Logging.Event.MaxBackups != 7 || !cfg.Logging.Event.CompressEnabled() {
		t.Fatalf("event logging = %+v, want own defaults with file override", cfg.Logging.Event)
	}
}

func TestResponseActionsConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := ResponseActionsConfig{}
	if cfg.TCPSynAck.TCPSeq != 0 {
		t.Fatalf("tcp_syn_ack.tcp_seq = %d, want 0 zero-value", cfg.TCPSynAck.TCPSeq)
	}
}

func TestLoadRejectsInvalidResponseConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "negative combined channels",
			body: "combined_channels: -1",
			want: "dataplane.combined_channels must be >= 0",
		},
		{
			name: "negative queue",
			body: "runtime:\n    queues: [-1]",
			want: "response: runtime: queue -1 out of range",
		},
		{
			name: "duplicate queue",
			body: "runtime:\n    queues: [0, 0]",
			want: "response: runtime: duplicate queue 0",
		},
		{
			name: "negative result buffer",
			body: "runtime:\n    result_buffer_size: -1",
			want: "response: runtime: result_buffer_size must be >= 0",
		},
		{
			name: "invalid hardware address",
			body: "actions:\n    arp_reply:\n      hardware_addr: nope",
			want: "response: actions: hardware_addr",
		},
		{
			name: "non ethernet hardware address",
			body: "actions:\n    arp_reply:\n      hardware_addr: 02:aa:bb:cc:dd:ee:ff:00",
			want: "response: actions: hardware_addr must be a 6-byte ethernet address",
		},
		{
			name: "reject old response tx block",
			body: "tx:\n    mode: egress-interface",
			want: "field tx not found",
		},
		{
			name: "reject old flat runtime enabled",
			body: "enabled: true",
			want: "field enabled not found",
		},
		{
			name: "reject old flat afxdp field",
			body: "frame_count: 4096",
			want: "field frame_count not found",
		},
		{
			name: "reject old flat action block",
			body: "arp_reply:\n    hardware_addr: nope",
			want: "field arp_reply not found",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prefix := `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0
`
			responseBody := tc.body
			if tc.name == "negative combined channels" {
				prefix += "  " + tc.body + "\n"
				responseBody = ""
			}

			path := writeConfigFile(t, prefix+`

response:
  `+responseBody+`

console:
  listen_addr: 127.0.0.1:8080
`)

			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want response validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsInvalidEgressConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "bad vlan mode",
			body: "vlan_mode: tagged",
			want: `egress: vlan_mode "tagged" is not valid`,
		},
		{
			name: "bad failure verdict",
			body: "failure_verdict: reject",
			want: `egress: failure_verdict "reject" is not valid`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

egress:
  `+tc.body+`

console:
  listen_addr: 127.0.0.1:8080
`)

			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want egress validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsInvalidConsoleStatsConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "bad collect interval",
			body: "collect_interval: bad\n    retention: 30d",
			want: "console.stats: collect_interval",
		},
		{
			name: "collect interval too large",
			body: "collect_interval: 11m\n    retention: 30d",
			want: "console.stats: collect_interval must be <= 10m",
		},
		{
			name: "bad retention",
			body: "collect_interval: 10s\n    retention: bad",
			want: "console.stats: retention",
		},
		{
			name: "retention too small",
			body: "collect_interval: 10s\n    retention: 5m",
			want: "console.stats: retention must be >= 10m",
		},
		{
			name: "retention smaller than collect interval",
			body: "collect_interval: 30m\n    retention: 20m",
			want: "console.stats: collect_interval must be <= 10m",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

console:
  listen_addr: 127.0.0.1:8080
  stats:
    `+tc.body+`
`)

			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want console stats validation error")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsInvalidDataplaneIngressVerdict(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0
  ingress_verdict: reject

console:
  listen_addr: 127.0.0.1:8080
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want dataplane validation error")
	}
	if !strings.Contains(err.Error(), `dataplane.ingress_verdict "reject" is not valid`) {
		t.Fatalf("Load() error = %q, want dataplane ingress verdict validation error", err)
	}
}

func dataplaneIngressVerdictLine(verdict string) string {
	if verdict == "" {
		return ""
	}
	return "  ingress_verdict: " + verdict + "\n"
}

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	return path
}
