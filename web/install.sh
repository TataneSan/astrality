#!/usr/bin/env bash
set -euo pipefail

SERVER_URL=""
ENROLL_TOKEN=""
VERSION="latest"
PUBKEY=""
SHA256_SUM=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/astrality"
INSECURE_ENROLL_TLS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER_URL="$2"; shift 2 ;;
    --token)
      ENROLL_TOKEN="$2"; shift 2 ;;
    --version)
      VERSION="$2"; shift 2 ;;
    --pubkey)
      PUBKEY="$2"; shift 2 ;;
    --sha256)
      SHA256_SUM="$2"; shift 2 ;;
    --insecure-enroll-tls)
      INSECURE_ENROLL_TLS="$2"; shift 2 ;;
    *)
      echo "unknown arg: $1" >&2
      exit 1 ;;
  esac
done

if [[ -z "$SERVER_URL" || -z "$ENROLL_TOKEN" ]]; then
  echo "usage: install.sh --server https://control-plane:8443 --token <token> [--version vX.Y.Z|latest] [--pubkey <minisign-pubkey>] [--sha256 <sha256>] [--insecure-enroll-tls true|false]" >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

BIN_NAME="astrality-agent-linux-${ARCH}"
if [[ "$VERSION" == "latest" ]]; then
  BIN_URL="${SERVER_URL%/}/artifacts/${BIN_NAME}"
else
  BIN_URL="${SERVER_URL%/}/artifacts/${VERSION}/${BIN_NAME}"
fi
SIG_URL="${BIN_URL}.minisig"

CURL_OPTS=(-fsSL)
if [[ "${INSECURE_ENROLL_TLS}" == "true" ]]; then
  CURL_OPTS+=(-k)
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
TMP_BIN="$(mktemp)"
trap 'rm -f "$TMP_BIN" /tmp/astrality-agent.minisig' EXIT

curl "${CURL_OPTS[@]}" "$BIN_URL" -o "$TMP_BIN"

if [[ -n "$PUBKEY" ]]; then
  if ! command -v minisign >/dev/null 2>&1; then
    echo "minisign required when --pubkey is set" >&2
    exit 1
  fi
  curl "${CURL_OPTS[@]}" "$SIG_URL" -o "/tmp/astrality-agent.minisig"
  minisign -V -P "$PUBKEY" -m "$TMP_BIN" -x "/tmp/astrality-agent.minisig"
fi

if [[ -n "$SHA256_SUM" ]]; then
  ACTUAL_SHA="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
  if [[ "$ACTUAL_SHA" != "$SHA256_SUM" ]]; then
    echo "sha256 mismatch" >&2
    exit 1
  fi
fi

install -m 0755 "$TMP_BIN" "${INSTALL_DIR}/astrality-agent"

cat > "${CONFIG_DIR}/agent.env" <<ENV
SERVER_URL=${SERVER_URL}
ENROLL_TOKEN=${ENROLL_TOKEN}
DATA_DIR=${CONFIG_DIR}
INSECURE_ENROLL_TLS=${INSECURE_ENROLL_TLS}
AGENT_ENV_FILE=${CONFIG_DIR}/agent.env
JOB_POLL_SEC=5
JOB_ALLOWLIST=uname,uptime,df,free,echo,cat,ls,systemctl,journalctl
ENV
chmod 600 "${CONFIG_DIR}/agent.env"

cat > /etc/systemd/system/astrality-agent.service <<SERVICE
[Unit]
Description=astrality agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=-${CONFIG_DIR}/agent.env
ExecStart=${INSTALL_DIR}/astrality-agent
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now astrality-agent
systemctl status --no-pager astrality-agent || true

echo "installed"
