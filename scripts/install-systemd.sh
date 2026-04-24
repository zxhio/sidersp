#!/usr/bin/env bash
set -euo pipefail

APP_NAME="sidersp"
INSTALL_BIN="/usr/local/bin/sidersp"
CONFIG_DIR="/etc/sidersp"
CONFIG_DEST="${CONFIG_DIR}/config.yaml"
RULES_DIR="${CONFIG_DIR}/configs"
RULES_DEST="${RULES_DIR}/rules.example.yaml"
LOG_DIR="/var/log/sidersp"
UNIT_DEST="/etc/systemd/system/sidersp.service"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

BINARY_SRC="${REPO_ROOT}/build/sidersp"
CONFIG_SRC="${REPO_ROOT}/configs/config.example.yaml"
RULES_SRC="${REPO_ROOT}/configs/rules.example.yaml"
UNIT_SRC="${REPO_ROOT}/deploy/systemd/sidersp.service"

DRY_RUN=0
FORCE=0
ENABLE_SERVICE=0
START_SERVICE=0

usage() {
  cat <<'USAGE'
Usage: scripts/install-systemd.sh [options]

Install SideSP for single-host Linux systemd deployment.

Options:
  --force     Overwrite existing config and rules.
  --enable    Enable sidersp.service.
  --start     Start sidersp.service after installation, or restart it if already running.
  --dry-run   Print actions without changing the system.
  -h, --help  Show this help.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "$*"
}

print_cmd() {
  printf 'dry-run:'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
}

run() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    print_cmd "$@"
    return 0
  fi
  "$@"
}

start_or_restart_service() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    log "dry-run: would restart ${APP_NAME}.service if already running, otherwise start it"
    return 0
  fi

  if systemctl is-active --quiet "${APP_NAME}.service"; then
    log "restart ${APP_NAME}.service"
    systemctl restart "${APP_NAME}.service"
    return 0
  fi

  log "start ${APP_NAME}.service"
  systemctl start "${APP_NAME}.service"
}

install_file() {
  local mode="$1"
  local src="$2"
  local dest="$3"

  if [[ -e "${dest}" && ${FORCE} -ne 1 ]]; then
    log "keep existing ${dest}; pass --force to overwrite"
    return 0
  fi

  run install -m "${mode}" "${src}" "${dest}"
}

require_environment() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    if [[ "$(uname -s)" != "Linux" ]]; then
      log "dry-run: real install requires Linux; current kernel is $(uname -s)"
    fi
    if [[ "${EUID}" -ne 0 ]]; then
      log "dry-run: real install requires root"
    fi
    return 0
  fi

  [[ "$(uname -s)" == "Linux" ]] || die "systemd deployment must run on Linux"
  [[ "${EUID}" -eq 0 ]] || die "systemd deployment must run as root; retry with sudo"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    --enable)
      ENABLE_SERVICE=1
      shift
      ;;
    --start)
      START_SERVICE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -f "${CONFIG_SRC}" ]] || die "config source not found: ${CONFIG_SRC}"
[[ -f "${RULES_SRC}" ]] || die "rules source not found: ${RULES_SRC}"
[[ -f "${UNIT_SRC}" ]] || die "systemd unit template not found: ${UNIT_SRC}"
if [[ ! -f "${BINARY_SRC}" ]]; then
  if [[ ${DRY_RUN} -eq 1 ]]; then
    log "dry-run: binary not found at ${BINARY_SRC}; real install requires make build-all"
  else
    die "binary not found at ${BINARY_SRC}; run make build-all first"
  fi
fi

require_environment

log "install plan:"
log "  binary: ${BINARY_SRC} -> ${INSTALL_BIN}"
log "  config: ${CONFIG_SRC} -> ${CONFIG_DEST}"
log "  rules: ${RULES_SRC} -> ${RULES_DEST}"
log "  logs: ${LOG_DIR}"
log "  unit: ${UNIT_SRC} -> ${UNIT_DEST}"

run install -d -m 0755 "${CONFIG_DIR}"
run install -d -m 0755 "${RULES_DIR}"
run install -d -m 0755 "${LOG_DIR}"
run install -m 0755 "${BINARY_SRC}" "${INSTALL_BIN}"
install_file 0644 "${CONFIG_SRC}" "${CONFIG_DEST}"
install_file 0644 "${RULES_SRC}" "${RULES_DEST}"
run install -m 0644 "${UNIT_SRC}" "${UNIT_DEST}"
run systemctl daemon-reload

if [[ ${ENABLE_SERVICE} -eq 1 ]]; then
  run systemctl enable "${APP_NAME}.service"
fi

if [[ ${START_SERVICE} -eq 1 ]]; then
  start_or_restart_service
fi

log "done"
