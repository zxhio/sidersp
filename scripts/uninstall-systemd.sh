#!/usr/bin/env bash
set -euo pipefail

APP_NAME="sidersp"
INSTALL_BIN="/usr/local/bin/sidersp"
CONFIG_DIR="/etc/sidersp"
UNIT_DEST="/etc/systemd/system/sidersp.service"

DRY_RUN=0
PURGE_CONFIG=0

usage() {
  cat <<'USAGE'
Usage: scripts/uninstall-systemd.sh [options]

Remove the SideSP single-host systemd deployment.

Options:
  --purge-config   Remove /etc/sidersp as well. By default config and rules are kept.
  --dry-run        Print actions without changing the system.
  -h, --help       Show this help.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "$*"
}

shell_quote() {
  printf "%q" "$1"
}

print_cmd() {
  printf 'dry-run:'
  for arg in "$@"; do
    printf ' %s' "$(shell_quote "$arg")"
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

require_real_uninstall_environment() {
  if [[ ${DRY_RUN} -eq 1 ]]; then
    if [[ "$(uname -s)" != "Linux" ]]; then
      log "dry-run: real uninstall requires Linux; current kernel is $(uname -s)"
    fi
    if [[ "${EUID}" -ne 0 ]]; then
      log "dry-run: real uninstall requires root"
    fi
    return 0
  fi

  [[ "$(uname -s)" == "Linux" ]] || die "systemd deployment uninstall must run on Linux"
  [[ "${EUID}" -eq 0 ]] || die "systemd deployment uninstall must run as root; retry with sudo"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-config)
      PURGE_CONFIG=1
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

require_real_uninstall_environment

log "uninstall plan:"
log "  stop: ${APP_NAME}.service"
log "  disable: ${APP_NAME}.service"
log "  remove unit: ${UNIT_DEST}"
log "  remove binary: ${INSTALL_BIN}"
log "  purge config: ${PURGE_CONFIG}"

if [[ ${DRY_RUN} -eq 1 ]]; then
  print_cmd systemctl stop "${APP_NAME}.service"
  print_cmd systemctl disable "${APP_NAME}.service"
else
  systemctl stop "${APP_NAME}.service" >/dev/null 2>&1 || true
  systemctl disable "${APP_NAME}.service" >/dev/null 2>&1 || true
fi

run rm -f "${UNIT_DEST}"
run rm -f "${INSTALL_BIN}"

if [[ ${PURGE_CONFIG} -eq 1 ]]; then
  run rm -rf "${CONFIG_DIR}"
else
  log "keep ${CONFIG_DIR}; pass --purge-config to remove it"
fi

run systemctl daemon-reload
log "done"
