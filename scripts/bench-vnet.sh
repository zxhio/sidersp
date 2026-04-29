#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

: "${BENCHTIME:=3s}"
: "${SIDERSP_VNET_SAMPLES:=100}"
: "${GOCACHE:=/tmp/sidersp-gocache}"
: "${SIDERSP_VNET_NAMESPACE:=ns-sidersp}"
: "${SIDERSP_VNET_BRIDGE_IFACE:=br-sidersp}"
: "${SIDERSP_VNET_INGRESS_IFACE:=vh-sidersp}"
: "${SIDERSP_VNET_PEER_IFACE:=vp-sidersp}"

VNET_HOST_CIDR="${SIDERSP_VNET_HOST_IP:-198.18.0.1}/29"
VNET_PEER_CIDR="${SIDERSP_VNET_PEER_IP:-198.18.0.2}/29"
VNET_HOST_IP="${SIDERSP_VNET_HOST_IP:-198.18.0.1}"
VNET_PEER_IP="${SIDERSP_VNET_PEER_IP:-198.18.0.2}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-vnet requires Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "bench-vnet requires root" >&2
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "bench-vnet requires the ip command" >&2
  exit 1
fi

cleanup_topology() {
  ip link set "${SIDERSP_VNET_INGRESS_IFACE}" nomaster >/dev/null 2>&1 || true
  ip link del "${SIDERSP_VNET_INGRESS_IFACE}" >/dev/null 2>&1 || true
  ip link del "${SIDERSP_VNET_BRIDGE_IFACE}" type bridge >/dev/null 2>&1 || true
  ip netns del "${SIDERSP_VNET_NAMESPACE}" >/dev/null 2>&1 || true
}

setup_topology() {
  cleanup_topology

  ip netns add "${SIDERSP_VNET_NAMESPACE}"
  ip link add name "${SIDERSP_VNET_BRIDGE_IFACE}" type bridge
  ip link add "${SIDERSP_VNET_INGRESS_IFACE}" type veth peer name "${SIDERSP_VNET_PEER_IFACE}"
  ip link set "${SIDERSP_VNET_PEER_IFACE}" netns "${SIDERSP_VNET_NAMESPACE}"

  ip link set "${SIDERSP_VNET_INGRESS_IFACE}" master "${SIDERSP_VNET_BRIDGE_IFACE}"
  ip addr add "${VNET_HOST_CIDR}" dev "${SIDERSP_VNET_BRIDGE_IFACE}"
  ip link set "${SIDERSP_VNET_BRIDGE_IFACE}" up
  ip link set "${SIDERSP_VNET_INGRESS_IFACE}" up

  ip netns exec "${SIDERSP_VNET_NAMESPACE}" ip link set lo up
  ip netns exec "${SIDERSP_VNET_NAMESPACE}" ip addr add "${VNET_PEER_CIDR}" dev "${SIDERSP_VNET_PEER_IFACE}"
  ip netns exec "${SIDERSP_VNET_NAMESPACE}" ip link set "${SIDERSP_VNET_PEER_IFACE}" up

  local bridge_mac
  local peer_mac
  bridge_mac="$(cat "/sys/class/net/${SIDERSP_VNET_BRIDGE_IFACE}/address")"
  peer_mac="$(ip netns exec "${SIDERSP_VNET_NAMESPACE}" cat "/sys/class/net/${SIDERSP_VNET_PEER_IFACE}/address")"

  ip neigh replace "${VNET_PEER_IP}" lladdr "${peer_mac}" dev "${SIDERSP_VNET_BRIDGE_IFACE}" nud permanent
  ip netns exec "${SIDERSP_VNET_NAMESPACE}" ip neigh replace "${VNET_HOST_IP}" lladdr "${bridge_mac}" dev "${SIDERSP_VNET_PEER_IFACE}" nud permanent
}

trap cleanup_topology EXIT
setup_topology

export SIDERSP_RUN_VNET_BENCH=1
export SIDERSP_VNET_SAMPLES
export SIDERSP_VNET_NAMESPACE
export SIDERSP_VNET_BRIDGE_IFACE
export SIDERSP_VNET_INGRESS_IFACE
export SIDERSP_VNET_PEER_IFACE
export GOCACHE

go test ./internal/vnetbench -run '^TestVnetLatencyMatrix$' -v -count=1
go test ./internal/vnetbench -run '^$' -bench '^BenchmarkVnet' -benchmem -benchtime="${BENCHTIME}" -count=1
