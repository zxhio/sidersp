//go:build linux

package response

import (
	"os"
	"testing"

	"github.com/google/gopacket/layers"
)

const defaultAFPacketBenchmarkInterface = "lo"

func BenchmarkExecuteTCPSynAckAFPacketSend(b *testing.B) {
	requireAFPacketBenchmarkEnv(b)

	ifaceName := os.Getenv("SIDERSP_BENCH_AF_PACKET_IFACE")
	if ifaceName == "" {
		ifaceName = defaultAFPacketBenchmarkInterface
	}

	out, err := newAFPacketFrameSender(ifaceName)
	if err != nil {
		b.Fatalf("newAFPacketFrameSender(%q) error = %v", ifaceName, err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			b.Fatalf("Close() error = %v", err)
		}
	}()

	frame := buildTestXSKFrame(b, XSKMetadata{
		RuleID: 1003,
		Action: ActionTCPSynAck,
	}, buildLoopbackTCPSyn(b))

	results := newTestResultBuffer(b, 1024)
	executor, err := NewResponseExecutor(ResponseExecutorConfig{
		IfIndex: 1,
		QueueID: 3,
		Sender: &afpacketSender{
			out:       out,
			buildOpts: testTCPSynAckBuildOptions(b, 1003, 1000),
		},
		Results: results,
		Stats:   newResponseStatsCounters(),
	})
	if err != nil {
		b.Fatalf("NewResponseExecutor() error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	benchmarkExecuteXSKFrame(b, executor, frame)
}

func requireAFPacketBenchmarkEnv(b *testing.B) {
	b.Helper()
	if testing.Short() {
		b.Skip("skip AF_PACKET benchmark in short mode")
	}
	if os.Getenv("SIDERSP_RUN_AF_PACKET_BENCH") != "1" {
		b.Skip("set SIDERSP_RUN_AF_PACKET_BENCH=1 to run AF_PACKET send benchmark")
	}
}

func buildLoopbackTCPSyn(t testing.TB) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("127.0.0.1"), DstIP: ip("127.0.0.1"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345, DstPort: 80,
		Seq: 42, SYN: true, Window: 4096,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set tcp checksum layer: %v", err)
	}
	return serializeTestLayers(t, eth, ip4, tcp)
}
