# Benchmark and Hotspot Analysis

## Test Environment

| Item | Value |
| --- | --- |
| OS | Debian, kernel 6.1.0-10-amd64 |
| CPU | 12th Gen Intel Core i7-12700 (12 cores / 20 threads, max 4.9 GHz) |
| Go | 1.25.5 linux/amd64 |
| `make bench` | `BENCHTIME=200ms` |
| `make bench-vnet` | `BENCHTIME=200ms`, `VNET_SAMPLES=5` |

## Entry Points

```bash
# pure benchmark aggregation
make bench

# vnet-backed end-to-end benchmark
sudo make bench-vnet
```

`make bench` runs three groups in sequence:

- kernel `tcp_reset`
- packet build and packet processing
- packet processing with real send

`make bench-vnet` creates a fixed `bridge + veth + netns` topology and then
runs the vnet latency check plus the end-to-end packet benchmarks.

## Benchmark Scenarios

### 1. BPF Kernel TCP Reset

**Path**: test packet injection → XDP rule match → `XDP_TX`

This is the in-kernel `tcp_reset` path.

| Packet Type | Value |
| --- | --- |
| Input | TCP SYN |
| Output | TCP RST/ACK |

| Metric | Value |
| --- | --- |
| ns/op | 769.5 |
| allocs | 1 |
| bytes | 320 B/op |
| PPS | 1.30M |
| gbps | 0.62 |

The single allocation is still the `cilium/ebpf` test harness buffer, not the
packet path itself.

### 2. Packet Build

**Path**: parse input → build response frame

These are the pure packet construction benchmarks in userspace.

| Scenario | Packet Type | ns/op | allocs/op |
| --- | --- | --- | --- |
| ICMP echo reply build | ICMP echo request -> ICMP echo reply | 109.6 | 1 |
| ARP reply build | ARP request -> ARP reply | 97.51 | 2 |
| TCP SYN-ACK build | TCP SYN -> TCP SYN-ACK | 93.41 | 1 |

The remaining `1 alloc/op` cases come from returning a fresh output buffer; they
are not extra protocol work in the packet logic itself.

### 3. Packet Processing (Stub Send)

**Path**: parse packet → build response → write to local sink

This covers the userspace hot path without a real kernel send.

| Scenario | Packet Type | ns/op | allocs/op | PPS |
| --- | --- | --- | --- | --- |
| ICMP echo reply processing | ICMP echo request -> ICMP echo reply | 156.4 | 0 | 6.39M |
| ARP reply processing | ARP request -> ARP reply | 164.6 | 1 | 6.08M |
| TCP SYN-ACK processing | TCP SYN -> TCP SYN-ACK | 154.8 | 0 | 6.46M |

### 4. Packet Processing + Real Send

**Path**: parse packet → build response → `AF_PACKET` send

This is the real userspace send path and is the third step inside `make bench`.

| Scenario | Packet Type | ns/op | allocs/op | PPS |
| --- | --- | --- | --- | --- |
| TCP SYN-ACK processing with real send | TCP SYN -> TCP SYN-ACK | 2468 | 1 | 405K |

### 5. VNET End-to-End

**Path**: `bridge + veth + netns` → peer raw probe → host packet path → peer receive

| Scenario | Packet Type | Baseline ns/op | SideRSP ns/op | Baseline PPS | SideRSP PPS | Delta |
| --- | --- | --- | --- | --- | --- | --- |
| ICMP | ICMP echo request -> ICMP echo reply | 2563 | 7241 | 400K | 140K | `+182.5%` |
| TCP SYN | TCP SYN -> TCP SYN-ACK | 6385 | 7656 | 158K | 132K | `+19.9%` |
| TCP reset | TCP SYN -> TCP RST/ACK | 3339 | 1897 | 306K | 547K | `-43.2%` |

The reply scenario uses port `18080`; the reset scenario uses port `18081`.

## Profiling Commands

```bash
# benchmark aggregation
BENCHTIME=1s make bench
BENCHTIME=1s VNET_SAMPLES=20 sudo make bench-vnet

# CPU profiles
BENCHTIME=5s make bench-response-pprof
BENCHTIME=5s make bench-bpf-pprof

# perf records
BENCHTIME=5s make bench-response-perf
BENCHTIME=5s make bench-bpf-perf

# inspect pprof
go tool pprof build/bench/response_bench.test build/bench/pprof/bench-response.cpu.pprof
go tool pprof build/bench/dataplane_bench.test build/bench/pprof/bench-bpf.cpu.pprof

# inspect perf
perf report -i build/bench/perf/bench-response.perf.data
perf report -i build/bench/perf/bench-bpf.perf.data
```

Artifacts are written to `build/bench/`:

```text
build/bench/
  dataplane_bench.test
  response_bench.test
  perf/
    bench-bpf.perf.data
    bench-response.perf.data
  pprof/
    bench-bpf.cpu.pprof
    bench-response.cpu.pprof
```
