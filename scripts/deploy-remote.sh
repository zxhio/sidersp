#!/usr/bin/env bash
set -euo pipefail

APP_NAME="sidersp"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"

usage() {
  cat <<'USAGE'
Usage: scripts/deploy-remote.sh --host <host>

Build a full release package and deploy it to a remote host over SSH.
The remote install keeps the existing config file.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "$*"
}

upload_file() {
  local src="$1"
  local host="$2"
  local dst="$3"

  if scp -o BatchMode=yes "${src}" "${host}:${dst}" >/dev/null 2>&1; then
    return 0
  fi
  ssh -o BatchMode=yes "${host}" "cat > '${dst}'" < "${src}"
}

HOST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"
      shift 2
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

[[ -n "${HOST}" ]] || die "--host is required"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BUILD_TS="$(date +%Y%m%d-%H%M%S)"
VERSION="${VERSION:-deploy-${BUILD_TS}}"
PACKAGE_NAME="${APP_NAME}-${VERSION}-${GOOS}-${GOARCH}"
LOCAL_PACKAGE="${REPO_ROOT}/dist/${PACKAGE_NAME}.tar.gz"
LOCAL_BINARY="${REPO_ROOT}/build/${APP_NAME}"

log "build package"
GOCACHE=/tmp/go-build TMPDIR=/tmp make package VERSION="${VERSION}" GOOS="${GOOS}" GOARCH="${GOARCH}"

[[ -f "${LOCAL_PACKAGE}" ]] || die "local package not found: ${LOCAL_PACKAGE}"

REMOTE_TS="$(ssh -o BatchMode=yes "${HOST}" date +%Y%m%d-%H%M%S)"
REMOTE_PACKAGE="/tmp/${PACKAGE_NAME}.tar.gz"
REMOTE_WORKDIR="/tmp/${PACKAGE_NAME}-${REMOTE_TS}"
LOCAL_SUM="$(sha256sum "${LOCAL_PACKAGE}" | awk '{print $1}')"

log "stop service"
ssh -o BatchMode=yes "${HOST}" "systemctl stop ${APP_NAME} || true"

log "backup binary/config"
ssh -o BatchMode=yes "${HOST}" "rm -f /usr/local/bin/${APP_NAME}.bak-* && test ! -f /usr/local/bin/${APP_NAME} || cp /usr/local/bin/${APP_NAME} /usr/local/bin/${APP_NAME}.old"
ssh -o BatchMode=yes "${HOST}" "rm -f /etc/sidersp/config.yaml.bak-* && test ! -f /etc/sidersp/config.yaml || cp /etc/sidersp/config.yaml /etc/sidersp/config.yaml.old"

log "upload package"
upload_file "${LOCAL_PACKAGE}" "${HOST}" "${REMOTE_PACKAGE}"

REMOTE_SUM="$(ssh -o BatchMode=yes "${HOST}" "sha256sum '${REMOTE_PACKAGE}' | awk '{print \$1}'")"
[[ "${LOCAL_SUM}" == "${REMOTE_SUM}" ]] || die "remote package checksum mismatch"

log "extract and install"
ssh -o BatchMode=yes "${HOST}" "rm -rf '${REMOTE_WORKDIR}' && mkdir -p '${REMOTE_WORKDIR}' && tar -xzf '${REMOTE_PACKAGE}' -C '${REMOTE_WORKDIR}' && cd '${REMOTE_WORKDIR}/${PACKAGE_NAME}' && ./scripts/install-systemd.sh --start"

log "cleanup remote tmp files"
ssh -o BatchMode=yes "${HOST}" "rm -f '${REMOTE_PACKAGE}' && rm -rf '${REMOTE_WORKDIR}'"

log "cleanup local build files"
rm -f "${LOCAL_PACKAGE}" "${LOCAL_BINARY}"

log "service status"
ssh -o BatchMode=yes "${HOST}" "systemctl status --no-pager ${APP_NAME}"
