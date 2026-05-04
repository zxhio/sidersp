# Test Layers and Benchmarks

This document separates correctness checks, privileged integration paths, and
performance measurements. Use the smallest layer that matches the change.

## Execution Layers

| Layer | Command | Scope | Requirements |
| --- | --- | --- | --- |
| Correctness | `make test` | Default Go correctness checks across packages. Privileged tests stay skipped unless their env gate is enabled. | Linux build deps for `go generate ./internal/dataplane` |
| Kernel integration | `make test-bpf` | Dataplane BPF integration tests under `internal/dataplane/` | Linux, root or matching capabilities, `SIDERSP_RUN_BPF_TESTS=1` |
| VNET integration | `sudo make test-vnet` | End-to-end vnet latency matrix under `internal/vnetbench/` | Linux, root, `SIDERSP_RUN_VNET_BENCH=1`, prepared netns/bridge/veth env |
| Microbenchmarks | `make bench` | Kernel dataplane microbenchmarks plus userspace build/execute/send benchmarks | Benchmark env vars as needed |
| End-to-end performance | `sudo make bench-vnet` | VNET-backed latency and throughput loops | Linux, root, prepared vnet env |

`make test-privileged` runs the kernel and vnet integration layers together.
Use it only on a host that already satisfies the vnet setup requirements.

## Performance Goals

Performance work in SideRSP protects the fast path first. Measure every change
against the path it can interfere with, not only against aggregate throughput.
For the user-space response path, treat `AF_XDP recv -> xsk dispatch ->
response execute/TX` as the primary hot path. Costs introduced only for
analysis must stay off that path, even when analysis is enabled.

Required reporting for end-to-end latency runs:

- Success count and failure count
- Average latency
- `p50`, `p95`, and `p99` latency
- Max latency
- PPS for the successful responses

Comparison matrix for Step 1:

| Scenario | Baseline | SideRSP path | Required comparison |
| --- | --- | --- | --- |
| Kernel reset | host baseline loop | `tcp_reset` in BPF | `make bench`, `make test-bpf`, and vnet loop comparison |
| User-space same-interface reply | host baseline loop | AF_XDP reply path | `make bench` packet-processing group plus vnet loop comparison |
| User-space egress reply | same request with no egress indirection | AF_PACKET egress reply path | `make bench` real-send group with `RESPONSE_SEND_IFACE=<iface>` |
| Analysis interference | analysis disabled | analysis export enabled on the same host profile | Compare `p95`/`p99` deltas and note whether response latency regresses |

Until analysis interference has a dedicated automated benchmark, record that
comparison as a host-level before/after run with the same traffic pattern,
queue layout, and attach mode.

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
# correctness
make test
make test-bpf
sudo make test-vnet

# pure benchmark aggregation
make bench

# vnet-backed end-to-end benchmark
sudo make bench-vnet
```

`make test` is the default correctness layer. It keeps normal package tests in
one entry point and relies on env-gated skips for host-specific paths.

`make test-bpf` isolates privileged dataplane correctness from the rest of the
Go suite.

`make test-vnet` isolates the vnet-backed integration chain from both unit-ish
tests and microbenchmarks.

`make bench` runs four performance groups in sequence:

- kernel dataplane microbenchmarks, including `tcp_reset` and flow-cache warm/cold candidate-scan runs
- rule snapshot sync microbenchmarks, including full rewrite and incremental apply on a large ruleset
- packet build and packet processing
- packet processing with real send

`make bench-vnet` creates a fixed `bridge + veth + netns` topology and then
runs the vnet latency check plus the end-to-end packet benchmarks.

`make test-vnet` logs `avg`, `min`, `p50`, `p95`, `p99`, `max`, and `count`
for each loop scenario. Keep those values with the corresponding `BENCHTIME`,
`VNET_SAMPLES`, attach mode, queue layout, and egress mode when comparing runs.

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
| ns/op | 731.1 |
| allocs | 1 |
| bytes | 320 B/op |
| PPS | 1.37M |
| gbps | 0.66 |

The single allocation is still the `cilium/ebpf` test harness buffer, not the
packet path itself.

### 2. Packet Build

**Path**: parse input → build response frame

These are the pure packet construction benchmarks in userspace.

| Scenario | Packet Type | ns/op | allocs/op |
| --- | --- | --- | --- |
| ICMP echo reply build | ICMP echo request -> ICMP echo reply | 237.2 | 1 |
| ARP reply build | ARP request -> ARP reply | 216.9 | 1 |
| TCP SYN-ACK build | TCP SYN -> TCP SYN-ACK | 255.9 | 1 |

The remaining `1 alloc/op` cases are the returned output buffer for the
standalone build helper. They are not extra packet-path work inside the
queue-local response execution path.

### 3. Packet Processing (Stub Send)

**Path**: parse packet → build response → write to local sink

This covers the userspace hot path without a real kernel send.

| Scenario | Packet Type | ns/op | allocs/op | PPS |
| --- | --- | --- | --- | --- |
| ICMP echo reply processing | ICMP echo request -> ICMP echo reply | 305.4 | 0 | 3.27M |
| ARP reply processing | ARP request -> ARP reply | 282.4 | 0 | 3.54M |
| TCP SYN-ACK processing | TCP SYN -> TCP SYN-ACK | 334.9 | 0 | 2.99M |

The success path for these queue-local execution benchmarks is now zero
allocation.

### 4. Packet Processing + Real Send

**Path**: parse packet → build response → `AF_PACKET` send

This is the real userspace send path and is the third step inside `make bench`.

| Scenario | Packet Type | ns/op | allocs/op | PPS |
| --- | --- | --- | --- | --- |
| TCP SYN-ACK processing with real send | TCP SYN -> TCP SYN-ACK | 2469 | 1 | 405K |

### 5. XSK Response Hot Path

**Path**: `AF_XDP recv -> xsk dispatch -> response execute/TX`

These targeted microbenchmarks are not part of `make bench`, but they track the
queue-local hot path more directly than the generic build/execute group.

| Scenario | Path Slice | ns/op | allocs/op |
| --- | --- | --- | --- |
| XSK worker dispatch noop | borrowed AF_XDP recv -> handler call | 5.0 | 0 |
| Runtime handle XSK ICMP echo reply | decoded envelope -> response execute/TX | 316.1 | 0 |
| XSK worker to response ICMP echo reply | borrowed AF_XDP recv -> dispatch -> response execute/TX | 330.0 | 0 |

Current implementation status for the primary response hot path:

- AF_XDP borrowed receive no longer does a fixed RX copy before response execution
- XSK worker borrowed receive no longer allocates a per-packet closure
- Queue-local response execution for the measured ICMP, ARP, and TCP SYN-ACK
  success paths is zero allocation
- Analysis remains an asynchronous side path and must absorb its own copy or
  buffering cost

### 6. VNET End-to-End

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
