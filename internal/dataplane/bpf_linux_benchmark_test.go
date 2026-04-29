//go:build linux

package dataplane

import (
	"os"
	"testing"
	"time"

	"sidersp/internal/rule"
)

var benchmarkKernelTCPResetRules = []rule.Rule{
	{
		ID:       9001,
		Name:     "bench_tcp_reset",
		Enabled:  true,
		Priority: 100,
		Match: tcpSynMatch(rule.RuleMatch{
			DstPrefixes: []string{"198.18.0.2/32"},
			DstPorts:    []int{18080},
		}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
}

var benchmarkKernelTCPResetPacket = buildEthernetPkt(ip("198.18.0.1"), ip("198.18.0.2"), 40000, 18080, "tcp_syn")

func BenchmarkBPFKernelTCPReset(b *testing.B) {
	requireBPFBenchmarkEnv(b)

	objs, reader := setupBPFRuntime(b, benchmarkKernelTCPResetRules)
	defer reader.Close()
	defer objs.Close()

	beforeTX := readStat(b, objs, statXDPTX)
	beforeMatch := readStat(b, objs, statMatchedRules)

	b.SetBytes(int64(len(benchmarkKernelTCPResetPacket)))
	b.ReportAllocs()
	b.ResetTimer()
	startedAt := time.Now()
	for i := 0; i < b.N; i++ {
		ret, _, err := objs.XdpSidersp.Test(benchmarkKernelTCPResetPacket)
		if err != nil {
			b.Fatalf("prog.Test() error = %v", err)
		}
		if ret != uint32(xdpTX) {
			b.Fatalf("prog.Test() retval = %d, want %d", ret, xdpTX)
		}
	}
	elapsed := time.Since(startedAt)
	b.StopTimer()
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "pps")
	b.ReportMetric(float64(len(benchmarkKernelTCPResetPacket)*8*b.N)/elapsed.Seconds()/1e9, "gbps")

	if got := readStat(b, objs, statXDPTX) - beforeTX; got != uint64(b.N) {
		b.Fatalf("xdp_tx delta = %d, want %d", got, b.N)
	}
	if got := readStat(b, objs, statMatchedRules) - beforeMatch; got != uint64(b.N) {
		b.Fatalf("matched_rules delta = %d, want %d", got, b.N)
	}
}

func requireBPFBenchmarkEnv(b *testing.B) {
	b.Helper()
	if testing.Short() {
		b.Skip("skip benchmark in short mode")
	}
	if os.Getenv("SIDERSP_RUN_BPF_TESTS") != "1" {
		b.Skip("set SIDERSP_RUN_BPF_TESTS=1 to run BPF kernel benchmarks")
	}
}
