#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-astrality.local}"
CONTROL_ADDR="${CONTROL_ADDR:-:8443}"
DB_NAME="${DB_NAME:-astrality}"
DB_USER="${DB_USER:-astrality}"
DB_PASS="${DB_PASS:-astrality-change-me}"
DATA_DIR="${DATA_DIR:-/var/lib/astrality}"
INSTALL_DIR="${INSTALL_DIR:-/opt/astrality}"
KEYCLOAK_VERSION="${KEYCLOAK_VERSION:-26.1.0}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-change-me-now}"
KEYCLOAK_HTTP_PORT="${KEYCLOAK_HTTP_PORT:-8081}"
BASTION_HOST="${BASTION_HOST:-bastion.internal}"

if [[ "$EUID" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

apt-get update
apt-get install -y ca-certificates curl jq unzip tar openssl postgresql postgresql-contrib openssh-server prometheus

if ! id -u astrality >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin astrality
fi
if ! id -u keycloak >/dev/null 2>&1; then
  useradd --system --home /opt/keycloak --shell /usr/sbin/nologin keycloak
fi

mkdir -p "$INSTALL_DIR" "$DATA_DIR" /etc/astrality /etc/astrality/tls
chown -R astrality:astrality "$INSTALL_DIR" "$DATA_DIR"

if command -v /usr/local/go/bin/go >/dev/null 2>&1; then
  export PATH=/usr/local/go/bin:$PATH
fi

cd "$ROOT_DIR"
make build
install -m 0755 bin/control-plane "$INSTALL_DIR/control-plane"

# PostgreSQL
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

# Keycloak DB
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='keycloak'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE keycloak;"
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='keycloak'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE ROLE keycloak LOGIN PASSWORD '${KEYCLOAK_ADMIN_PASS}';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;" || true

# TLS self-signed fallback
if [[ ! -f /etc/astrality/tls/server.crt || ! -f /etc/astrality/tls/server.key ]]; then
  openssl req -x509 -newkey rsa:3072 -keyout /etc/astrality/tls/server.key -out /etc/astrality/tls/server.crt \
    -sha256 -days 365 -nodes -subj "/CN=${DOMAIN}"
  chmod 600 /etc/astrality/tls/server.key
fi

cat > /etc/astrality/control-plane.env <<ENV
HTTP_ADDR=${CONTROL_ADDR}
DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}?sslmode=disable
DATA_DIR=${DATA_DIR}
BASTION_HOST=${BASTION_HOST}
TLS_CERT_FILE=/etc/astrality/tls/server.crt
TLS_KEY_FILE=/etc/astrality/tls/server.key
OIDC_ISSUER=http://127.0.0.1:${KEYCLOAK_HTTP_PORT}/realms/astrality
OIDC_AUDIENCE=astrality-ui
DB_TIMEOUT_SEC=5
ENROLL_RATE_PER_MINUTE=30
HEARTBEAT_OFFLINE_SEC=60
ENV
chmod 600 /etc/astrality/control-plane.env

install -m 0644 "$ROOT_DIR/deploy/systemd/astrality-control-plane.service" /etc/systemd/system/astrality-control-plane.service

# Keycloak install
if [[ ! -d /opt/keycloak/bin ]]; then
  curl -fsSL "https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz" -o /tmp/keycloak.tgz
  rm -rf /opt/keycloak
  mkdir -p /opt/keycloak
  tar -xzf /tmp/keycloak.tgz -C /opt/keycloak --strip-components=1
  chown -R keycloak:keycloak /opt/keycloak
fi

cat > /etc/systemd/system/keycloak.service <<SERVICE
[Unit]
Description=Keycloak
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=keycloak
Group=keycloak
Environment=KC_DB=postgres
Environment=KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/keycloak
Environment=KC_DB_USERNAME=keycloak
Environment=KC_DB_PASSWORD=${KEYCLOAK_ADMIN_PASS}
Environment=KC_HTTP_ENABLED=true
Environment=KC_HTTP_PORT=${KEYCLOAK_HTTP_PORT}
Environment=KC_HOSTNAME=127.0.0.1
Environment=KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN_USER}
Environment=KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASS}
ExecStart=/opt/keycloak/bin/kc.sh start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now keycloak

# Provision realm/client/roles
cat > /tmp/provision-keycloak.sh <<KCSH
#!/usr/bin/env bash
set -euo pipefail
export KEYCLOAK_URL="http://127.0.0.1:${KEYCLOAK_HTTP_PORT}"
/opt/keycloak/bin/kcadm.sh config credentials --server "\$KEYCLOAK_URL" --realm master --user "${KEYCLOAK_ADMIN_USER}" --password "${KEYCLOAK_ADMIN_PASS}"
if ! /opt/keycloak/bin/kcadm.sh get realms/astrality >/dev/null 2>&1; then
  /opt/keycloak/bin/kcadm.sh create realms -s realm=astrality -s enabled=true
fi
if ! /opt/keycloak/bin/kcadm.sh get clients -r astrality -q clientId=astrality-ui | grep -q astrality-ui; then
  /opt/keycloak/bin/kcadm.sh create clients -r astrality \
    -s clientId=astrality-ui \
    -s enabled=true \
    -s publicClient=true \
    -s directAccessGrantsEnabled=true \
    -s standardFlowEnabled=true
fi
for role in viewer operator admin; do
  /opt/keycloak/bin/kcadm.sh create roles -r astrality -s name=\$role >/dev/null 2>&1 || true
done
KCSH
chmod +x /tmp/provision-keycloak.sh

for _ in $(seq 1 30); do
  if curl -fsSL "http://127.0.0.1:${KEYCLOAK_HTTP_PORT}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
bash /tmp/provision-keycloak.sh || true

# Prometheus target setup
cp "$ROOT_DIR/ops/prometheus.yml" /etc/prometheus/prometheus.yml
systemctl restart prometheus || true

systemctl enable --now astrality-control-plane

echo "setup complete"
echo "Control-plane: https://${DOMAIN}${CONTROL_ADDR}"
echo "Keycloak: http://127.0.0.1:${KEYCLOAK_HTTP_PORT}"
