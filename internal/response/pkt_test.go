package response

import (
	"testing"

	"github.com/google/gopacket"
)

var benchmarkDecodeSink gopacket.LayerType

func BenchmarkDecodeICMPEchoRequest(b *testing.B) {
	benchmarkDecode(b, buildTestICMPEchoRequest(b))
}

func BenchmarkDecodeARPRequest(b *testing.B) {
	benchmarkDecode(b, buildTestARPRequest(b))
}

func BenchmarkDecodeTCPSyn(b *testing.B) {
	benchmarkDecode(b, buildTestTCPSyn(b))
}

func BenchmarkDecodeDNSQuery(b *testing.B) {
	benchmarkDecode(b, buildTestDNSQuery(b, "example.org"))
}

func benchmarkDecode(b *testing.B, frame []byte) {
	b.Helper()

	var pkt Packet

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := pkt.Decode(frame, nil, "bench"); err != nil {
			b.Fatalf("Decode() error = %v", err)
		}
		benchmarkDecodeSink = pkt.layerType
	}
}
