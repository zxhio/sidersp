//go:build linux

package dataplane

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"sidersp/internal/rule"
)

const (
	benchmarkRuleSyncRuleCount     = 256
	benchmarkRuleSyncChangedRules  = 16
	benchmarkFlowCacheFalseMatches = 255
	benchmarkFlowCachePacketCount  = 1024
)

func BenchmarkBPFRuleSyncLargeRuleSet(b *testing.B) {
	baseSet, nextSet := benchmarkRuleSyncRuleSets(benchmarkRuleSyncRuleCount, benchmarkRuleSyncChangedRules)
	baseSnapshot, err := buildSnapshot(baseSet, Options{})
	require.NoError(b, err, "build base snapshot")
	nextSnapshot, err := buildSnapshot(nextSet, Options{})
	require.NoError(b, err, "build next snapshot")

	b.Run("build_snapshot_256_rules", func(b *testing.B) {
		b.ReportAllocs()
		b.ReportMetric(float64(benchmarkRuleSyncRuleCount), "rules")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			set := baseSet
			if i%2 == 1 {
				set = nextSet
			}
			if _, err := buildSnapshot(set, Options{}); err != nil {
				b.Fatalf("buildSnapshot() error = %v", err)
			}
		}
	})

	b.Run("write_full_256_rules", func(b *testing.B) {
		runtime := setupBenchmarkRuntime(b)
		b.ReportAllocs()
		b.ReportMetric(float64(benchmarkRuleSyncRuleCount), "rules")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			snapshot := baseSnapshot
			if i%2 == 1 {
				snapshot = nextSnapshot
			}
			if err := runtime.writeFullSnapshot(snapshot); err != nil {
				b.Fatalf("writeFullSnapshot() error = %v", err)
			}
		}
	})

	b.Run("apply_incremental_256_rules_16_changes", func(b *testing.B) {
		runtime := setupBenchmarkRuntime(b)
		require.NoError(b, runtime.applySnapshot(baseSnapshot), "prime snapshot")
		snapshots := []mapSnapshot{baseSnapshot, nextSnapshot}
		nextIdx := 1

		b.ReportAllocs()
		b.ReportMetric(float64(benchmarkRuleSyncRuleCount), "rules")
		b.ReportMetric(float64(benchmarkRuleSyncChangedRules), "changed_rules")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := runtime.applySnapshot(snapshots[nextIdx]); err != nil {
				b.Fatalf("applySnapshot() error = %v", err)
			}
			nextIdx ^= 1
		}
	})
}

func BenchmarkBPFFlowCacheCandidateScan(b *testing.B) {
	rules := benchmarkFlowCacheRules(benchmarkFlowCacheFalseMatches)
	coldPackets := benchmarkFlowCachePackets(benchmarkFlowCachePacketCount)
	warmPacket := buildEthernetPkt(ip("198.18.0.1"), ip("198.18.0.2"), 45000, 18080, "tcp_syn")

	b.Run("cold_miss_255_false_candidates", func(b *testing.B) {
		requireBPFBenchmarkEnv(b)
		objs := setupDrainingBenchmarkRuntime(b, rules)
		beforeMatch := readStat(b, objs, statMatchedRules)

		b.SetBytes(int64(len(coldPackets[0])))
		b.ReportAllocs()
		b.ResetTimer()
		startedAt := time.Now()
		for i := 0; i < b.N; i++ {
			ret, _, err := objs.XdpSidersp.Test(coldPackets[i%len(coldPackets)])
			if err != nil {
				b.Fatalf("prog.Test() error = %v", err)
			}
			if ret != uint32(xdpTX) {
				b.Fatalf("prog.Test() retval = %d, want %d", ret, xdpTX)
			}
		}
		reportBenchmarkRates(b, startedAt, len(coldPackets[0]))

		if got := readStat(b, objs, statMatchedRules) - beforeMatch; got != uint64(b.N) {
			b.Fatalf("matched_rules delta = %d, want %d", got, b.N)
		}
	})

	b.Run("warm_hit_255_false_candidates", func(b *testing.B) {
		requireBPFBenchmarkEnv(b)
		objs := setupDrainingBenchmarkRuntime(b, rules)
		ret, _, err := objs.XdpSidersp.Test(warmPacket)
		require.NoError(b, err, "prime prog.Test()")
		require.Equal(b, uint32(xdpTX), ret, "prime prog.Test() retval")
		beforeMatch := readStat(b, objs, statMatchedRules)

		b.SetBytes(int64(len(warmPacket)))
		b.ReportAllocs()
		b.ResetTimer()
		startedAt := time.Now()
		for i := 0; i < b.N; i++ {
			ret, _, err := objs.XdpSidersp.Test(warmPacket)
			if err != nil {
				b.Fatalf("prog.Test() error = %v", err)
			}
			if ret != uint32(xdpTX) {
				b.Fatalf("prog.Test() retval = %d, want %d", ret, xdpTX)
			}
		}
		reportBenchmarkRates(b, startedAt, len(warmPacket))

		if got := readStat(b, objs, statMatchedRules) - beforeMatch; got != uint64(b.N) {
			b.Fatalf("matched_rules delta = %d, want %d", got, b.N)
		}
	})
}

func setupBenchmarkRuntime(b *testing.B) *Runtime {
	b.Helper()
	requireBPFBenchmarkEnv(b)
	require.NoError(b, rlimit.RemoveMemlock(), "remove memlock")

	var objs siderspObjects
	require.NoError(b, loadSiderspObjects(&objs, nil), "load BPF objects")
	b.Cleanup(func() {
		_ = objs.Close()
	})

	return &Runtime{objs: objs}
}

func setupDrainingBenchmarkRuntime(b *testing.B, rules []rule.Rule) *siderspObjects {
	b.Helper()
	objs, reader := setupBPFRuntime(b, rules)
	done := make(chan struct{})
	go func() {
		defer close(done)
		drainBenchmarkEvents(reader)
	}()
	b.Cleanup(func() {
		_ = reader.Close()
		<-done
		_ = objs.Close()
	})
	return objs
}

func drainBenchmarkEvents(reader *ringbuf.Reader) {
	for {
		if _, err := reader.Read(); err != nil {
			return
		}
	}
}

func reportBenchmarkRates(b *testing.B, startedAt time.Time, frameLen int) {
	b.Helper()
	elapsed := time.Since(startedAt)
	b.StopTimer()
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "pps")
	b.ReportMetric(float64(frameLen*8*b.N)/elapsed.Seconds()/1e9, "gbps")
}

func benchmarkRuleSyncRuleSets(totalRules, changedRules int) (rule.RuleSet, rule.RuleSet) {
	baseRules := make([]rule.Rule, 0, totalRules)
	nextRules := make([]rule.Rule, 0, totalRules)

	for i := 0; i < totalRules; i++ {
		basePrefix := benchmarkRulePrefix(i)
		basePort := 20000 + i
		nextPrefix := basePrefix
		nextPort := basePort
		if i < changedRules {
			nextPrefix = benchmarkRulePrefix(i + totalRules)
			nextPort = 30000 + i
		}

		baseRules = append(baseRules, rule.Rule{
			ID:       10000 + i,
			Name:     fmt.Sprintf("bench_sync_base_%d", i),
			Enabled:  true,
			Priority: 100 + i,
			Match: tcpSynMatch(rule.RuleMatch{
				DstPrefixes: []string{basePrefix},
				DstPorts:    []int{basePort},
			}),
			Response: rule.RuleResponse{Action: "tcp_reset"},
		})
		nextRules = append(nextRules, rule.Rule{
			ID:       10000 + i,
			Name:     fmt.Sprintf("bench_sync_next_%d", i),
			Enabled:  true,
			Priority: 100 + i,
			Match: tcpSynMatch(rule.RuleMatch{
				DstPrefixes: []string{nextPrefix},
				DstPorts:    []int{nextPort},
			}),
			Response: rule.RuleResponse{Action: "tcp_reset"},
		})
	}

	return rule.RuleSet{Rules: baseRules}, rule.RuleSet{Rules: nextRules}
}

func benchmarkRulePrefix(i int) string {
	addr := netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0})
	return netip.PrefixFrom(addr, 24).String()
}

func benchmarkFlowCacheRules(falseMatchCount int) []rule.Rule {
	rules := make([]rule.Rule, 0, falseMatchCount+1)
	for i := 0; i < falseMatchCount; i++ {
		rules = append(rules, rule.Rule{
			ID:       20000 + i,
			Name:     fmt.Sprintf("bench_flow_cache_false_%d", i),
			Enabled:  true,
			Priority: 100 + i,
			Match: rule.RuleMatch{
				Protocol:    "tcp",
				DstPrefixes: []string{"198.18.0.2/32"},
				DstPorts:    []int{18080},
				TCPFlags:    rule.TCPFlags{ACK: boolPtr(true)},
			},
			Response: rule.RuleResponse{Action: "tcp_reset"},
		})
	}
	rules = append(rules, rule.Rule{
		ID:       30000,
		Name:     "bench_flow_cache_match",
		Enabled:  true,
		Priority: 1000,
		Match: rule.RuleMatch{
			Protocol:    "tcp",
			DstPrefixes: []string{"198.18.0.2/32"},
			DstPorts:    []int{18080},
		},
		Response: rule.RuleResponse{Action: "tcp_reset"},
	})
	return rules
}

func benchmarkFlowCachePackets(count int) [][]byte {
	packets := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		packets = append(packets, buildEthernetPkt(
			ip("198.18.0.1"),
			ip("198.18.0.2"),
			uint16(40000+i),
			18080,
			"tcp_syn",
		))
	}
	return packets
}
