#!/usr/bin/env bash

set -euo pipefail

BENCHTIME="${BENCHTIME:-200ms}"
BENCH_GOCACHE="${BENCH_GOCACHE:-/tmp/sidersp-gocache}"
BPF_BENCH_GATE="${BPF_BENCH_GATE:-^BenchmarkBPFKernelTCPReset$}"
BPF_BENCH_NS_MAX="${BPF_BENCH_NS_MAX:-1500}"
RESPONSE_BENCH_GATE="${RESPONSE_BENCH_GATE:-^BenchmarkExecuteTCPSynAck$}"
RESPONSE_BENCH_NS_MAX="${RESPONSE_BENCH_NS_MAX:-400}"

extract_ns_per_op() {
	local output_file="$1"
	awk '/^Benchmark/ {for (i = 1; i <= NF; i++) if ($i == "ns/op") {print $(i - 1); exit}}' "$output_file"
}

assert_ns_threshold() {
	local label="$1"
	local actual_ns="$2"
	local max_ns="$3"

	awk -v label="$label" -v actual="$actual_ns" -v limit="$max_ns" '
	BEGIN {
		if ((actual + 0) > (limit + 0)) {
			printf "%s failed: %.3f ns/op > %.3f ns/op\n", label, actual, limit > "/dev/stderr"
			exit 1
		}
		printf "%s ok: %.3f ns/op <= %.3f ns/op\n", label, actual, limit
	}'
}

run_gate() {
	local label="$1"
	local max_ns="$2"
	shift 2

	local output_file
	output_file="$(mktemp)"
	if ! "$@" | tee "$output_file"; then
		rm -f "$output_file"
		return 1
	fi

	local actual_ns
	actual_ns="$(extract_ns_per_op "$output_file")"
	rm -f "$output_file"

	if [[ -z "$actual_ns" ]]; then
		echo "missing ns/op output for ${label}" >&2
		return 1
	fi

	assert_ns_threshold "$label" "$actual_ns" "$max_ns"
}

echo "bench-gate BENCHTIME=${BENCHTIME}"
echo "bench-gate BPF_BENCH_NS_MAX=${BPF_BENCH_NS_MAX} RESPONSE_BENCH_NS_MAX=${RESPONSE_BENCH_NS_MAX}"

run_gate \
	"bpf_kernel_tcp_reset" \
	"${BPF_BENCH_NS_MAX}" \
	env GOCACHE="${BENCH_GOCACHE}" SIDERSP_RUN_BPF_TESTS=1 \
	go test ./internal/dataplane/ -run '^$' -bench "${BPF_BENCH_GATE}" -benchmem -benchtime "${BENCHTIME}" -count 1

run_gate \
	"response_execute_tcp_syn_ack" \
	"${RESPONSE_BENCH_NS_MAX}" \
	env GOCACHE="${BENCH_GOCACHE}" \
	go test ./internal/response/ -run '^$' -bench "${RESPONSE_BENCH_GATE}" -benchmem -benchtime "${BENCHTIME}" -count 1
