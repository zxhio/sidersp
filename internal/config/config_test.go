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
	if cfg.Dataplane.NormalizedIngressVerdict() != "pass" {
		t.Fatalf("Dataplane ingress verdict = %q, want pass", cfg.Dataplane.NormalizedIngressVerdict())
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
			if got := cfg.Dataplane.NormalizedIngressVerdict(); got != tc.want {
				t.Fatalf("Dataplane.NormalizedIngressVerdict() = %q, want %q", got, tc.want)
			}
		})
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
	if got := cfg.Response.Runtime.WorkerQueues(); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("WorkerQueues() = %+v, want [0 1]", got)
	}
	if cfg.Response.Runtime.ResultBufferCapacity() != 2048 {
		t.Fatalf("ResultBufferCapacity() = %d, want 2048", cfg.Response.Runtime.ResultBufferCapacity())
	}
	if cfg.Response.Actions.ARPReply.HardwareAddr != "02:aa:bb:cc:dd:ee" || cfg.Response.Actions.TCPSynAck.TCPSeq != 1000 {
		t.Fatalf("Response = %+v, want arp_reply/tcp_syn_ack populated", cfg.Response)
	}
	if cfg.Egress.TXPath() != "egress-interface" ||
		cfg.Egress.Interface != "eth1" ||
		cfg.Egress.NormalizedVLANMode() != "access" ||
		cfg.Egress.NormalizedFailureVerdict() != "drop" {
		t.Fatalf("Egress = %+v, want egress-interface/access/drop", cfg.Egress)
	}
	if cfg.Response.Runtime.AFXDP.FrameSize != 4096 || cfg.Response.Runtime.AFXDP.TXFrameReserve != 256 {
		t.Fatalf("AFXDP = %+v, want frame_size=4096 tx_frame_reserve=256", cfg.Response.Runtime.AFXDP)
	}
}

func TestResponseConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := ResponseRuntimeConfig{}
	queues := cfg.WorkerQueues()
	if len(queues) != 1 || queues[0] != 0 {
		t.Fatalf("WorkerQueues() = %+v, want [0]", queues)
	}
	queues[0] = 10
	if next := cfg.WorkerQueues(); next[0] != 0 {
		t.Fatalf("WorkerQueues() returned mutable default, got %+v", next)
	}
	if cfg.ResultBufferCapacity() != 1024 {
		t.Fatalf("ResultBufferCapacity() = %d, want 1024", cfg.ResultBufferCapacity())
	}
}

func TestEgressConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := EgressConfig{}
	if cfg.TXPath() != "same-interface" {
		t.Fatalf("TXPath() = %q, want same-interface", cfg.TXPath())
	}
	if cfg.NormalizedVLANMode() != "preserve" {
		t.Fatalf("egress vlan mode = %q, want preserve", cfg.NormalizedVLANMode())
	}
	if cfg.NormalizedFailureVerdict() != "pass" {
		t.Fatalf("egress failure verdict = %q, want pass", cfg.NormalizedFailureVerdict())
	}
}

func TestResponseActionsConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := ResponseActionsConfig{}
	if cfg.TCPSynAck.TCPSeq != 0 {
		t.Fatalf("tcp_syn_ack.tcp_seq = %d, want 0 zero-value", cfg.TCPSynAck.TCPSeq)
	}
}

func TestDataplaneConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := DataplaneConfig{}
	if got := cfg.NormalizedIngressVerdict(); got != "pass" {
		t.Fatalf("NormalizedIngressVerdict() = %q, want pass", got)
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

			path := writeConfigFile(t, `controlplane:
  rules_path: configs/rules.example.yaml

dataplane:
  interface: eth0

response:
  `+tc.body+`

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
