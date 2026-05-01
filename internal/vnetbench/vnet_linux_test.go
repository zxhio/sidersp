//go:build linux

package vnetbench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sidersp/internal/dataplane"
	"sidersp/internal/logs"
	"sidersp/internal/response"
	"sidersp/internal/rule"
	"sidersp/internal/xsk"
	"sidersp/internal/xsk/afxdp"
)

const (
	envRunVnetBench     = "SIDERSP_RUN_VNET_BENCH"
	envVnetSamples      = "SIDERSP_VNET_SAMPLES"
	envVnetNamespace    = "SIDERSP_VNET_NAMESPACE"
	envVnetBridgeIface  = "SIDERSP_VNET_BRIDGE_IFACE"
	envVnetIngressIface = "SIDERSP_VNET_INGRESS_IFACE"
	envVnetPeerIface    = "SIDERSP_VNET_PEER_IFACE"
	defaultLoopSample   = 100

	loopTCPSYNPort    = 18080
	loopTCPResetPort  = 18081
	loopReadTimeout   = 2 * time.Second
	loopProbeDeadline = 5 * time.Second
	loopWarmupDelay   = 50 * time.Millisecond
)

var (
	loopHostIP    = netip.MustParseAddr("198.18.0.1")
	loopPeerIP    = netip.MustParseAddr("198.18.0.2")
	loopVirtualIP = netip.MustParseAddr("198.18.0.3")
	loopLogsOnce  sync.Once
)

type testingTB interface {
	Cleanup(func())
	Errorf(string, ...any)
	Fatalf(string, ...any)
	Helper()
	Logf(string, ...any)
	Skipf(string, ...any)
}

type loopHarness struct {
	t        testingTB
	env      *loopEnvironment
	runner   *namespaceProbeRunner
	listener net.Listener

	dataplane *dataplane.Runtime
	response  *response.Runtime

	cancel      context.CancelFunc
	responseErr chan error

	closeOnce sync.Once
}

type vnetMode uint8

const (
	vnetModeBaseline vnetMode = iota
	vnetModeSideRSP
)

type loopEnvironment struct {
	namespacePath string
	bridgeIfName  string
	ingressIfName string
	peerIfName    string
	bridgeMAC     net.HardwareAddr
}

func TestVnetLatencyMatrix(t *testing.T) {
	requireVnetBenchEnv(t)

	samples := vnetSampleCount(t)

	baseline := newVnetHarness(t, vnetModeBaseline)
	if err := baseline.WarmICMP(loopHostIP); err != nil {
		t.Fatalf("warm baseline icmp: %v", err)
	}
	if err := baseline.WarmSYN(loopHostIP); err != nil {
		t.Fatalf("warm baseline syn: %v", err)
	}
	if err := baseline.WarmRST(loopHostIP); err != nil {
		t.Fatalf("warm baseline rst: %v", err)
	}

	pingBaseline, err := baseline.runner.RunICMPLoop(loopHostIP, samples, loopReadTimeout, true)
	if err != nil {
		t.Fatalf("measure baseline icmp: %v", err)
	}
	synBaseline, err := baseline.runner.RunSYNLoop(loopHostIP, loopTCPSYNPort, samples, loopReadTimeout, true)
	if err != nil {
		t.Fatalf("measure baseline syn: %v", err)
	}
	rstBaseline, err := baseline.runner.RunRSTLoop(loopHostIP, loopTCPResetPort, samples, loopReadTimeout, true)
	if err != nil {
		t.Fatalf("measure baseline rst: %v", err)
	}
	if err := baseline.Close(); err != nil {
		t.Fatalf("close baseline harness: %v", err)
	}

	sideRSP := newVnetHarness(t, vnetModeSideRSP)
	if err := sideRSP.WarmICMP(loopVirtualIP); err != nil {
		t.Fatalf("warm SideRSP icmp: %v", err)
	}
	if err := sideRSP.WarmSYN(loopVirtualIP); err != nil {
		t.Fatalf("warm SideRSP syn: %v", err)
	}
	if err := sideRSP.WarmRST(loopVirtualIP); err != nil {
		t.Fatalf("warm SideRSP rst: %v", err)
	}

	pingSideRSP, err := sideRSP.runner.RunICMPLoop(loopVirtualIP, samples, loopReadTimeout, true)
	if err != nil {
		t.Fatalf("measure SideRSP icmp: %v", err)
	}
	synSideRSP, err := sideRSP.runner.RunSYNLoop(loopVirtualIP, loopTCPSYNPort, samples, loopReadTimeout, true)
	if err != nil {
		t.Fatalf("measure SideRSP syn: %v", err)
	}
	rstSideRSP, err := sideRSP.runner.RunRSTLoop(loopVirtualIP, loopTCPResetPort, samples, loopReadTimeout, true)
	if err != nil {
		t.Fatalf("measure SideRSP rst: %v", err)
	}

	if got := pingBaseline.Successes; got != samples {
		t.Fatalf("baseline icmp successes = %d, want %d", got, samples)
	}
	if got := synBaseline.Successes; got != samples {
		t.Fatalf("baseline syn successes = %d, want %d", got, samples)
	}
	if got := pingSideRSP.Successes; got != samples {
		t.Fatalf("SideRSP icmp successes = %d, want %d", got, samples)
	}
	if got := synSideRSP.Successes; got != samples {
		t.Fatalf("SideRSP syn successes = %d, want %d", got, samples)
	}
	if got := rstBaseline.Successes; got != samples {
		t.Fatalf("baseline rst successes = %d, want %d", got, samples)
	}
	if got := rstSideRSP.Successes; got != samples {
		t.Fatalf("SideRSP rst successes = %d, want %d", got, samples)
	}

	dpStats, err := sideRSP.dataplane.ReadStats()
	if err != nil {
		t.Fatalf("read SideRSP dataplane stats: %v", err)
	}
	respStats := sideRSP.response.ReadStats()
	if dpStats.MatchedRules < uint64(samples*3) {
		t.Fatalf("matched_rules = %d, want at least %d", dpStats.MatchedRules, samples*3)
	}
	if dpStats.XskRedirected < uint64(samples*2) {
		t.Fatalf("xsk_redirected = %d, want at least %d", dpStats.XskRedirected, samples*2)
	}
	if dpStats.XDPTX < uint64(samples) {
		t.Fatalf("xdp_tx = %d, want at least %d", dpStats.XDPTX, samples)
	}
	if respStats.ResponseSent < uint64(samples*2) {
		t.Fatalf("response_sent = %d, want at least %d", respStats.ResponseSent, samples*2)
	}
	if respStats.ResponseFailed != 0 {
		t.Fatalf("response_failed = %d, want 0", respStats.ResponseFailed)
	}

	logLatencySummary(t, "ping_baseline", summarizeLatencies(pingBaseline.Latencies))
	logLatencySummary(t, "ping_sidersp", summarizeLatencies(pingSideRSP.Latencies))
	logLatencySummary(t, "syn_baseline", summarizeLatencies(synBaseline.Latencies))
	logLatencySummary(t, "syn_sidersp", summarizeLatencies(synSideRSP.Latencies))
	logLatencySummary(t, "rst_baseline", summarizeLatencies(rstBaseline.Latencies))
	logLatencySummary(t, "rst_sidersp", summarizeLatencies(rstSideRSP.Latencies))
}

func BenchmarkVnetBaselineICMP(b *testing.B) {
	benchmarkVnetICMP(b, loopHostIP, vnetModeBaseline)
}

func BenchmarkVnetSideRSPICMP(b *testing.B) {
	benchmarkVnetICMP(b, loopVirtualIP, vnetModeSideRSP)
}

func BenchmarkVnetBaselineTCPSYN(b *testing.B) {
	benchmarkVnetSYN(b, loopHostIP, vnetModeBaseline)
}

func BenchmarkVnetSideRSPTCPSYN(b *testing.B) {
	benchmarkVnetSYN(b, loopVirtualIP, vnetModeSideRSP)
}

func BenchmarkVnetBaselineTCPReset(b *testing.B) {
	benchmarkVnetTCPReset(b, loopHostIP, vnetModeBaseline)
}

func BenchmarkVnetSideRSPTCPReset(b *testing.B) {
	benchmarkVnetTCPReset(b, loopVirtualIP, vnetModeSideRSP)
}

func benchmarkVnetICMP(b *testing.B, targetIP netip.Addr, mode vnetMode) {
	requireVnetBenchEnv(b)

	harness := newVnetHarness(b, mode)
	if err := harness.WarmICMP(targetIP); err != nil {
		b.Fatalf("warm icmp target %s: %v", targetIP, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	result, err := harness.runner.RunICMPLoop(targetIP, b.N, loopReadTimeout, false)
	b.StopTimer()
	if err != nil {
		b.Fatalf("run icmp benchmark: %v", err)
	}
	if result.Successes != b.N {
		b.Fatalf("icmp successes = %d, want %d", result.Successes, b.N)
	}
	if result.RequestSize > 0 {
		b.SetBytes(int64(result.RequestSize))
	}
	b.ReportMetric(float64(result.Successes)/result.Total.Seconds(), "pps")
	b.ReportMetric(float64(result.Successes)*100/float64(result.Count), "success_pct")
}

func benchmarkVnetSYN(b *testing.B, targetIP netip.Addr, mode vnetMode) {
	requireVnetBenchEnv(b)

	harness := newVnetHarness(b, mode)
	if err := harness.WarmSYN(targetIP); err != nil {
		b.Fatalf("warm syn target %s: %v", targetIP, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	result, err := harness.runner.RunSYNLoop(targetIP, loopTCPSYNPort, b.N, loopReadTimeout, false)
	b.StopTimer()
	if err != nil {
		b.Fatalf("run syn benchmark: %v", err)
	}
	if result.Successes != b.N {
		b.Fatalf("syn successes = %d, want %d", result.Successes, b.N)
	}
	if result.RequestSize > 0 {
		b.SetBytes(int64(result.RequestSize))
	}
	b.ReportMetric(float64(result.Successes)/result.Total.Seconds(), "pps")
	b.ReportMetric(float64(result.Successes)*100/float64(result.Count), "success_pct")
}

func benchmarkVnetTCPReset(b *testing.B, targetIP netip.Addr, mode vnetMode) {
	requireVnetBenchEnv(b)

	harness := newVnetHarness(b, mode)
	if err := harness.WarmRST(targetIP); err != nil {
		b.Fatalf("warm rst target %s: %v", targetIP, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	result, err := harness.runner.RunRSTLoop(targetIP, loopTCPResetPort, b.N, loopReadTimeout, false)
	b.StopTimer()
	if err != nil {
		b.Fatalf("run rst benchmark: %v", err)
	}
	if result.Successes != b.N {
		b.Fatalf("rst successes = %d, want %d", result.Successes, b.N)
	}
	if result.RequestSize > 0 {
		b.SetBytes(int64(result.RequestSize))
	}
	b.ReportMetric(float64(result.Successes)/result.Total.Seconds(), "pps")
	b.ReportMetric(float64(result.Successes)*100/float64(result.Count), "success_pct")
}

func newVnetHarness(tb testingTB, mode vnetMode) *loopHarness {
	tb.Helper()

	env := loadVnetEnvironment(tb)
	harness := &loopHarness{
		t:   tb,
		env: env,
		runner: newNamespaceProbeRunner(tb, namespaceProbeConfig{
			NamespacePath: env.namespacePath,
			InterfaceName: env.peerIfName,
			PeerIP:        loopPeerIP,
			HostIP:        loopHostIP,
			HostMAC:       env.bridgeMAC,
		}),
	}

	listener, err := net.Listen("tcp4", net.JoinHostPort(loopHostIP.String(), strconv.Itoa(loopTCPSYNPort)))
	if err != nil {
		_ = harness.Close()
		tb.Fatalf("listen on %s:%d: %v", loopHostIP, loopTCPSYNPort, err)
	}
	harness.listener = listener

	switch mode {
	case vnetModeSideRSP:
		if err := harness.startSideRSP(); err != nil {
			_ = harness.Close()
			tb.Fatalf("start SideRSP harness: %v", err)
		}
	}

	tb.Cleanup(func() {
		if err := harness.Close(); err != nil {
			tb.Errorf("close loop harness: %v", err)
		}
	})
	return harness
}

func (h *loopHarness) WarmICMP(targetIP netip.Addr) error {
	return h.waitForProbe(func() error {
		_, err := h.runner.RunICMPLoop(targetIP, 1, loopReadTimeout, false)
		return err
	})
}

func (h *loopHarness) WarmSYN(targetIP netip.Addr) error {
	return h.waitForProbe(func() error {
		_, err := h.runner.RunSYNLoop(targetIP, loopTCPSYNPort, 1, loopReadTimeout, false)
		return err
	})
}

func (h *loopHarness) WarmRST(targetIP netip.Addr) error {
	return h.waitForProbe(func() error {
		_, err := h.runner.RunRSTLoop(targetIP, loopTCPResetPort, 1, loopReadTimeout, false)
		return err
	})
}

func (h *loopHarness) waitForProbe(run func() error) error {
	var lastErr error
	deadline := time.Now().Add(loopProbeDeadline)
	for {
		if err := run(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(loopWarmupDelay)
	}
}

func (h *loopHarness) startSideRSP() error {
	hostIf, err := net.InterfaceByName(h.env.ingressIfName)
	if err != nil {
		return fmt.Errorf("lookup ingress interface %s: %w", h.env.ingressIfName, err)
	}

	afxdpCfg := afxdp.DefaultSocketConfig()
	afxdpCfg.IfIndex = hostIf.Index

	resp, err := response.NewRuntime(response.Options{
		IfIndex:          hostIf.Index,
		ResultBufferSize: 1024,
		HardwareAddr:     append(net.HardwareAddr(nil), h.env.bridgeMAC...),
		EgressInterface:  h.env.bridgeIfName,
	})
	if err != nil {
		return fmt.Errorf("create response runtime: %w", err)
	}
	h.response = resp

	dp, err := dataplane.Open(dataplane.Options{
		Interface:      h.env.ingressIfName,
		AttachMode:     "generic",
		IngressVerdict: "drop",
		XSK: xsk.Options{
			Enabled: true,
			IfIndex: hostIf.Index,
			Queues:  []int{0},
			AFXDP:   afxdpCfg,
		},
	}, dataplane.XSKConsumers{
		Response: resp,
	})
	if err != nil {
		_ = resp.Close()
		return fmt.Errorf("open dataplane runtime: %w", err)
	}
	h.dataplane = dp

	rules := sideRSPRuleSet()
	if err := resp.ReplaceRules(rules); err != nil {
		return fmt.Errorf("replace response rules: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.responseErr = make(chan error, 1)
	go func() {
		h.responseErr <- dp.RunXSK(ctx)
	}()

	time.Sleep(loopWarmupDelay)

	if err := dp.ReplaceRules(rules); err != nil {
		return fmt.Errorf("replace dataplane rules: %w", err)
	}
	return nil
}

func (h *loopHarness) Close() error {
	var closeErr error
	h.closeOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		if h.responseErr != nil {
			if err := <-h.responseErr; err != nil {
				closeErr = errors.Join(closeErr, err)
			}
		}
		if h.listener != nil {
			if err := h.listener.Close(); err != nil {
				closeErr = errors.Join(closeErr, err)
			}
			h.listener = nil
		}
		if h.response != nil {
			if err := h.response.Close(); err != nil {
				closeErr = errors.Join(closeErr, err)
			}
			h.response = nil
		}
		if h.dataplane != nil {
			if err := h.dataplane.Close(); err != nil {
				closeErr = errors.Join(closeErr, err)
			}
			h.dataplane = nil
		}
		if h.runner != nil {
			if err := h.runner.Close(); err != nil {
				closeErr = errors.Join(closeErr, err)
			}
			h.runner = nil
		}
	})
	return closeErr
}

func sideRSPRuleSet() rule.RuleSet {
	return rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID:       7001,
				Name:     "loop_icmp_echo_reply",
				Enabled:  true,
				Priority: 100,
				Match: rule.RuleMatch{
					Protocol:    "icmp",
					DstPrefixes: []string{loopVirtualIP.String() + "/32"},
					ICMP:        &rule.ICMPMatch{Type: "echo_request"},
				},
				Response: rule.RuleResponse{Action: "icmp_echo_reply"},
			},
			{
				ID:       7002,
				Name:     "loop_tcp_syn_ack",
				Enabled:  true,
				Priority: 110,
				Match: rule.RuleMatch{
					Protocol:    "tcp",
					DstPrefixes: []string{loopVirtualIP.String() + "/32"},
					DstPorts:    []int{loopTCPSYNPort},
					TCPFlags: rule.TCPFlags{
						SYN: boolPtr(true),
					},
				},
				Response: rule.RuleResponse{
					Action: "tcp_syn_ack",
					Params: map[string]any{"tcp_seq": 1},
				},
			},
			{
				ID:       7003,
				Name:     "vnet_tcp_reset",
				Enabled:  true,
				Priority: 100,
				Match: rule.RuleMatch{
					Protocol:    "tcp",
					DstPrefixes: []string{loopVirtualIP.String() + "/32"},
					DstPorts:    []int{loopTCPResetPort},
					TCPFlags: rule.TCPFlags{
						SYN: boolPtr(true),
					},
				},
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func vnetSampleCount(tb testingTB) int {
	tb.Helper()

	raw := strings.TrimSpace(os.Getenv(envVnetSamples))
	if raw == "" {
		return defaultLoopSample
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		tb.Fatalf("%s must be a positive integer, got %q", envVnetSamples, raw)
	}
	return value
}

func loadVnetEnvironment(tb testingTB) *loopEnvironment {
	tb.Helper()

	nsName := strings.TrimSpace(os.Getenv(envVnetNamespace))
	bridgeIfName := strings.TrimSpace(os.Getenv(envVnetBridgeIface))
	hostIfName := strings.TrimSpace(os.Getenv(envVnetIngressIface))
	peerIfName := strings.TrimSpace(os.Getenv(envVnetPeerIface))
	if nsName == "" || bridgeIfName == "" || hostIfName == "" || peerIfName == "" {
		tb.Fatalf("vnet benchmark requires %s, %s, %s, and %s", envVnetNamespace, envVnetBridgeIface, envVnetIngressIface, envVnetPeerIface)
	}

	bridgeIf, err := net.InterfaceByName(bridgeIfName)
	if err != nil {
		tb.Fatalf("lookup bridge interface %s: %v", bridgeIfName, err)
	}

	return &loopEnvironment{
		namespacePath: filepath.Join("/var/run/netns", nsName),
		bridgeIfName:  bridgeIfName,
		ingressIfName: hostIfName,
		peerIfName:    peerIfName,
		bridgeMAC:     append(net.HardwareAddr(nil), bridgeIf.HardwareAddr...),
	}
}

func requireVnetBenchEnv(tb testingTB) {
	tb.Helper()

	loopLogsOnce.Do(func() {
		logs.App().SetOutput(io.Discard)
		logs.Stats().SetOutput(io.Discard)
		logs.Event().SetOutput(io.Discard)
	})

	if testing.Short() {
		tb.Skipf("skip loop benchmark in short mode")
	}
	if os.Getenv(envRunVnetBench) != "1" {
		tb.Skipf("set %s=1 to run vnet benchmark tests", envRunVnetBench)
	}
	if os.Geteuid() != 0 {
		tb.Fatalf("vnet benchmark tests require root")
	}
	namespace := strings.TrimSpace(os.Getenv(envVnetNamespace))
	if _, err := os.Stat(filepath.Join("/var/run/netns", namespace)); err != nil {
		tb.Fatalf("vnet benchmark namespace %q is not ready: %v", namespace, err)
	}
}

func logLatencySummary(tb testingTB, label string, summary latencySummary) {
	tb.Helper()
	tb.Logf("%s_avg_ms=%s min_ms=%s p50_ms=%s p95_ms=%s max_ms=%s count=%d",
		label,
		formatDurationMS(summary.Avg),
		formatDurationMS(summary.Min),
		formatDurationMS(summary.P50),
		formatDurationMS(summary.P95),
		formatDurationMS(summary.Max),
		summary.Count,
	)
}
