#!/usr/bin/env bash
set -euo pipefail

APP_NAME="sidersp"
VERSION="${VERSION:-dev}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

BINARY_SRC="${REPO_ROOT}/build/sidersp"
DIST_DIR="${REPO_ROOT}/dist"
PACKAGE_NAME="${APP_NAME}-${VERSION}-${GOOS}-${GOARCH}"
PACKAGE_PATH="${DIST_DIR}/${PACKAGE_NAME}.tar.gz"

DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: scripts/package-release.sh [options]

Create a SideSP release tarball from the current build artifact.

Options:
  --dry-run   Print package inputs without writing files.
  -h, --help  Show this help.

Environment:
  VERSION     Release version. Default: dev.
  GOOS        Target OS label. Default: linux.
  GOARCH      Target architecture label. Default: amd64.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "$*"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

[[ -f "${REPO_ROOT}/configs/config.example.yaml" ]] || die "missing configs/config.example.yaml"
[[ -f "${REPO_ROOT}/configs/rules.example.yaml" ]] || die "missing configs/rules.example.yaml"
[[ -f "${REPO_ROOT}/deploy/systemd/sidersp.service" ]] || die "missing deploy/systemd/sidersp.service"
[[ -f "${REPO_ROOT}/scripts/install-systemd.sh" ]] || die "missing scripts/install-systemd.sh"
[[ -f "${REPO_ROOT}/scripts/uninstall-systemd.sh" ]] || die "missing scripts/uninstall-systemd.sh"
[[ -f "${REPO_ROOT}/docs/deployment.md" ]] || die "missing docs/deployment.md"
[[ "${VERSION}" =~ ^[A-Za-z0-9._-]+$ ]] || die "VERSION may only contain letters, numbers, dot, underscore, and dash"
[[ "${GOOS}" =~ ^[A-Za-z0-9._-]+$ ]] || die "GOOS may only contain letters, numbers, dot, underscore, and dash"
[[ "${GOARCH}" =~ ^[A-Za-z0-9._-]+$ ]] || die "GOARCH may only contain letters, numbers, dot, underscore, and dash"
if [[ ! -f "${BINARY_SRC}" ]]; then
  if [[ ${DRY_RUN} -eq 1 ]]; then
    log "dry-run: binary not found at ${BINARY_SRC}; real package requires make build-all"
  else
    die "binary not found at ${BINARY_SRC}; run make build-all first"
  fi
fi

log "package plan:"
log "  version: ${VERSION}"
log "  target: ${GOOS}/${GOARCH}"
log "  output: ${PACKAGE_PATH}"
log "  binary: ${BINARY_SRC}"

if [[ ${DRY_RUN} -eq 1 ]]; then
  exit 0
fi

mkdir -p "${DIST_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

PACKAGE_ROOT="${WORK_DIR}/${PACKAGE_NAME}"
mkdir -p "${PACKAGE_ROOT}/build"
mkdir -p "${PACKAGE_ROOT}/configs"
mkdir -p "${PACKAGE_ROOT}/deploy/systemd"
mkdir -p "${PACKAGE_ROOT}/scripts"
mkdir -p "${PACKAGE_ROOT}/docs"

install -m 0755 "${BINARY_SRC}" "${PACKAGE_ROOT}/build/sidersp"
install -m 0644 "${REPO_ROOT}/configs/config.example.yaml" "${PACKAGE_ROOT}/configs/config.example.yaml"
install -m 0644 "${REPO_ROOT}/configs/rules.example.yaml" "${PACKAGE_ROOT}/configs/rules.example.yaml"
install -m 0644 "${REPO_ROOT}/deploy/systemd/sidersp.service" "${PACKAGE_ROOT}/deploy/systemd/sidersp.service"
install -m 0755 "${REPO_ROOT}/scripts/install-systemd.sh" "${PACKAGE_ROOT}/scripts/install-systemd.sh"
install -m 0755 "${REPO_ROOT}/scripts/uninstall-systemd.sh" "${PACKAGE_ROOT}/scripts/uninstall-systemd.sh"
install -m 0644 "${REPO_ROOT}/docs/deployment.md" "${PACKAGE_ROOT}/docs/deployment.md"
install -m 0644 "${REPO_ROOT}/README.md" "${PACKAGE_ROOT}/README.md"
install -m 0644 "${REPO_ROOT}/README.zh-CN.md" "${PACKAGE_ROOT}/README.zh-CN.md"

cat > "${PACKAGE_ROOT}/RELEASE" <<EOF
name: ${APP_NAME}
version: ${VERSION}
target: ${GOOS}/${GOARCH}
install: sudo scripts/install-systemd.sh --enable --start
docs: docs/deployment.md
EOF

tar -czf "${PACKAGE_PATH}" -C "${WORK_DIR}" "${PACKAGE_NAME}"
log "created ${PACKAGE_PATH}"
