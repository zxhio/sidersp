APP := sidersp
MAIN := ./cmd/sidersp
BIN := ./build/$(APP)
CONFIG ?= ./configs/config.example.yaml
VERSION ?= dev
BPF_BENCH ?= BenchmarkBPF
BENCHTIME ?= 3s
BENCH ?= Benchmark(Decode|Build|Execute)
RESPONSE_SEND_BENCH ?= BenchmarkExecuteTCPSynAckAFPacketSend
RESPONSE_SEND_IFACE ?= lo
RESPONSE_PROFILE_BENCH ?= BenchmarkExecuteTCPSynAck
VNET_SAMPLES ?= 100
BENCH_BUILD_DIR ?= ./build/bench
BENCH_GOCACHE ?= /tmp/sidersp-gocache
BENCH_PERF_DIR ?= $(BENCH_BUILD_DIR)/perf
BENCH_PPROF_DIR ?= $(BENCH_BUILD_DIR)/pprof
BPF_BENCH_BIN := $(BENCH_BUILD_DIR)/dataplane_bench.test
RESPONSE_BENCH_BIN := $(BENCH_BUILD_DIR)/response_bench.test
BPF_PERF_DATA ?= $(BENCH_PERF_DIR)/bench-bpf.perf.data
RESPONSE_PERF_DATA ?= $(BENCH_PERF_DIR)/bench-response.perf.data
BPF_CPU_PPROF ?= $(BENCH_PPROF_DIR)/bench-bpf.cpu.pprof
RESPONSE_CPU_PPROF ?= $(BENCH_PPROF_DIR)/bench-response.cpu.pprof
PERF_RECORD_FLAGS ?= -g
GOOS := linux
GOARCH := amd64

.PHONY: build build-all build-web build-xdp package run clean test test-unit test-bpf ai-review bench bench-vnet bench-bpf-perf bench-response-perf bench-bpf-pprof bench-response-pprof

build: build-xdp build-web
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w" -o $(BIN) $(MAIN)

build-web:
	cd web && npm ci && npm run build

build-xdp:
	go generate ./internal/dataplane

build-all:
	$(MAKE) build

package: build-all
	VERSION=$(VERSION) GOOS=$(GOOS) GOARCH=$(GOARCH) scripts/package-release.sh

run: build-all
	$(BIN) -config $(CONFIG)

clean:
	rm -f $(BIN)
	rm -rf $(BENCH_BUILD_DIR)
	rm -f ./internal/dataplane/sidersp_bpfel.go
	rm -f ./internal/dataplane/sidersp_bpfel.o

test: test-unit

test-unit: build-xdp
	go test ./... -v -count=1

test-bpf: build-xdp
	SIDERSP_RUN_BPF_TESTS=1 go test ./internal/dataplane/ -v -count=1 -run TestBPF

ai-review:
	bash scripts/ai-review.sh

bench: build-xdp
	GOCACHE=$(BENCH_GOCACHE) SIDERSP_RUN_BPF_TESTS=1 go test ./internal/dataplane/ -run '^$$' -bench $(BPF_BENCH) -benchmem -benchtime=$(BENCHTIME) -count=1
	GOCACHE=$(BENCH_GOCACHE) go test ./internal/response/ -run '^$$' -bench '$(BENCH)' -benchmem -benchtime=$(BENCHTIME) -count=1
	GOCACHE=$(BENCH_GOCACHE) SIDERSP_RUN_AF_PACKET_BENCH=1 SIDERSP_BENCH_AF_PACKET_IFACE=$(RESPONSE_SEND_IFACE) go test ./internal/response/ -run '^$$' -bench $(RESPONSE_SEND_BENCH) -benchmem -benchtime=$(BENCHTIME) -count=1

bench-vnet: build-xdp
	GOCACHE=$(BENCH_GOCACHE) BENCHTIME=$(BENCHTIME) SIDERSP_VNET_SAMPLES=$(VNET_SAMPLES) scripts/bench-vnet.sh

bench-bpf-perf: build-xdp
	mkdir -p $(BENCH_BUILD_DIR) $(BENCH_PERF_DIR)
	GOCACHE=/tmp/sidersp-gocache go test -c -o $(BPF_BENCH_BIN) ./internal/dataplane/
	perf record $(PERF_RECORD_FLAGS) -o $(BPF_PERF_DATA) -- env SIDERSP_RUN_BPF_TESTS=1 $(BPF_BENCH_BIN) -test.run '^$$' -test.bench $(BPF_BENCH) -test.benchmem -test.benchtime $(BENCHTIME) -test.count 1
	@echo "perf.data written to $(BPF_PERF_DATA)"
	@echo "inspect with: perf report -i $(BPF_PERF_DATA)"

bench-response-perf:
	mkdir -p $(BENCH_BUILD_DIR) $(BENCH_PERF_DIR)
	GOCACHE=/tmp/sidersp-gocache go test -c -o $(RESPONSE_BENCH_BIN) ./internal/response/
	perf record $(PERF_RECORD_FLAGS) -o $(RESPONSE_PERF_DATA) -- $(RESPONSE_BENCH_BIN) -test.run '^$$' -test.bench $(RESPONSE_PROFILE_BENCH) -test.benchmem -test.benchtime $(BENCHTIME) -test.count 1
	@echo "perf.data written to $(RESPONSE_PERF_DATA)"
	@echo "inspect with: perf report -i $(RESPONSE_PERF_DATA)"

bench-bpf-pprof: build-xdp
	mkdir -p $(BENCH_BUILD_DIR) $(BENCH_PPROF_DIR)
	GOCACHE=/tmp/sidersp-gocache go test -c -o $(BPF_BENCH_BIN) ./internal/dataplane/
	env SIDERSP_RUN_BPF_TESTS=1 $(BPF_BENCH_BIN) -test.run '^$$' -test.bench $(BPF_BENCH) -test.benchmem -test.benchtime $(BENCHTIME) -test.count 1 -test.cpuprofile $(BPF_CPU_PPROF)
	@echo "pprof written to $(BPF_CPU_PPROF)"
	@echo "inspect with: go tool pprof $(BPF_BENCH_BIN) $(BPF_CPU_PPROF)"

bench-response-pprof:
	mkdir -p $(BENCH_BUILD_DIR) $(BENCH_PPROF_DIR)
	GOCACHE=/tmp/sidersp-gocache go test -c -o $(RESPONSE_BENCH_BIN) ./internal/response/
	$(RESPONSE_BENCH_BIN) -test.run '^$$' -test.bench $(RESPONSE_PROFILE_BENCH) -test.benchmem -test.benchtime $(BENCHTIME) -test.count 1 -test.cpuprofile $(RESPONSE_CPU_PPROF)
	@echo "pprof written to $(RESPONSE_CPU_PPROF)"
	@echo "inspect with: go tool pprof $(RESPONSE_BENCH_BIN) $(RESPONSE_CPU_PPROF)"
