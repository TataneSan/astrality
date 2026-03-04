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
KEYCLOAK_DB_PASS="${KEYCLOAK_DB_PASS:-$KEYCLOAK_ADMIN_PASS}"
KEYCLOAK_HTTP_PORT="${KEYCLOAK_HTTP_PORT:-8081}"
BASTION_HOST="${BASTION_HOST:-}"
CONSOLE_SSH_USER="${CONSOLE_SSH_USER:-root}"
CONSOLE_SSH_USERS="${CONSOLE_SSH_USERS:-root,ubuntu,debian,ec2-user,centos,admin}"
CONSOLE_TARGET_ORDER="${CONSOLE_TARGET_ORDER:-ip,hostname}"
CONSOLE_SSH_KEY_FILE="${CONSOLE_SSH_KEY_FILE:-}"
BOOTSTRAP_ADMIN_USER="${BOOTSTRAP_ADMIN_USER:-astrality-admin}"
BOOTSTRAP_ADMIN_PASS="${BOOTSTRAP_ADMIN_PASS:-$(openssl rand -hex 16)}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-}"
LOGIN_RATE_PER_MINUTE="${LOGIN_RATE_PER_MINUTE:-20}"

if [[ "$EUID" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v /usr/local/go/bin/go >/dev/null 2>&1; then
  export PATH=/usr/local/go/bin:$PATH
fi

declare -a POSTGRES_RUN
if command -v sudo >/dev/null 2>&1; then
  POSTGRES_RUN=(sudo -u postgres)
elif command -v runuser >/dev/null 2>&1; then
  POSTGRES_RUN=(runuser -u postgres --)
else
  echo "sudo or runuser is required" >&2
  exit 1
fi

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

DB_PASS_SQL="$(sql_escape "$DB_PASS")"
KEYCLOAK_DB_PASS_SQL="$(sql_escape "$KEYCLOAK_DB_PASS")"

apt-get update
apt-get install -y \
  ca-certificates curl jq unzip tar openssl \
  postgresql postgresql-contrib openssh-server prometheus openjdk-17-jre-headless

if ! id -u astrality >/dev/null 2>&1; then
  useradd --system --home /nonexistent --shell /usr/sbin/nologin astrality
fi
if ! id -u keycloak >/dev/null 2>&1; then
  useradd --system --home /opt/keycloak --shell /usr/sbin/nologin keycloak
fi

mkdir -p "$INSTALL_DIR" "$DATA_DIR" /etc/astrality /etc/astrality/tls
chown -R astrality:astrality "$INSTALL_DIR" "$DATA_DIR"
chown root:astrality /etc/astrality/tls
chmod 750 /etc/astrality/tls

cd "$ROOT_DIR"
make build
install -m 0755 bin/control-plane "$INSTALL_DIR/control-plane"

if ! make artifacts; then
  if [[ ! -f "$ROOT_DIR/artifacts/astrality-agent-linux-amd64" ]]; then
    echo "agent artifacts are missing and build failed" >&2
    exit 1
  fi
  echo "warning: make artifacts failed, using existing artifacts/" >&2
fi

install -d -m 0755 "$INSTALL_DIR/web" "$INSTALL_DIR/artifacts"
cp -a "$ROOT_DIR/web/." "$INSTALL_DIR/web/"
if [[ -d "$ROOT_DIR/artifacts" ]]; then
  cp -a "$ROOT_DIR/artifacts/." "$INSTALL_DIR/artifacts/"
fi
chown -R astrality:astrality "$INSTALL_DIR"
chmod -R a+rX "$INSTALL_DIR/web" "$INSTALL_DIR/artifacts"

# PostgreSQL
"${POSTGRES_RUN[@]}" psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
  "${POSTGRES_RUN[@]}" psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS_SQL}';"
"${POSTGRES_RUN[@]}" psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
  "${POSTGRES_RUN[@]}" psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

# Keycloak DB
"${POSTGRES_RUN[@]}" psql -tc "SELECT 1 FROM pg_roles WHERE rolname='keycloak'" | grep -q 1 || \
  "${POSTGRES_RUN[@]}" psql -c "CREATE ROLE keycloak LOGIN PASSWORD '${KEYCLOAK_DB_PASS_SQL}';"
"${POSTGRES_RUN[@]}" psql -tc "SELECT 1 FROM pg_database WHERE datname='keycloak'" | grep -q 1 || \
  "${POSTGRES_RUN[@]}" psql -c "CREATE DATABASE keycloak OWNER keycloak;"
"${POSTGRES_RUN[@]}" psql -c "ALTER DATABASE keycloak OWNER TO keycloak;" || true
"${POSTGRES_RUN[@]}" psql -d keycloak -c "ALTER SCHEMA public OWNER TO keycloak;" || true
"${POSTGRES_RUN[@]}" psql -d keycloak -c "GRANT ALL ON SCHEMA public TO keycloak;" || true
"${POSTGRES_RUN[@]}" psql -d keycloak -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO keycloak;" || true
"${POSTGRES_RUN[@]}" psql -d keycloak -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO keycloak;" || true

# Internal CA + server cert signed by that CA (agent-trusted mTLS path).
CA_CERT="${DATA_DIR}/ca.pem"
CA_KEY="${DATA_DIR}/ca-key.pem"
CA_SERIAL="${DATA_DIR}/ca.srl"
SERVER_CERT="/etc/astrality/tls/server.crt"
SERVER_KEY="/etc/astrality/tls/server.key"

if [[ ! -f "$CA_CERT" || ! -f "$CA_KEY" ]]; then
  openssl genrsa -out "$CA_KEY" 3072
  openssl req -x509 -new -key "$CA_KEY" -out "$CA_CERT" -sha256 -days 3650 \
    -subj "/O=astrality/CN=astrality-ca"
fi

TMP_TLS_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_TLS_DIR"' EXIT
LOCAL_HOST="$(hostname -f 2>/dev/null || hostname)"
{
  echo "[req]"
  echo "default_bits = 3072"
  echo "prompt = no"
  echo "default_md = sha256"
  echo "distinguished_name = dn"
  echo "req_extensions = req_ext"
  echo
  echo "[dn]"
  echo "CN = ${DOMAIN}"
  echo
  echo "[req_ext]"
  echo "subjectAltName = @alt_names"
  echo
  echo "[alt_names]"
  echo "IP.1 = 127.0.0.1"
  echo "DNS.1 = localhost"
  echo "DNS.2 = ${LOCAL_HOST}"
  if [[ "${DOMAIN}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "IP.2 = ${DOMAIN}"
  else
    echo "DNS.3 = ${DOMAIN}"
  fi
} > "${TMP_TLS_DIR}/server.cnf"

openssl genrsa -out "${TMP_TLS_DIR}/server.key" 3072
openssl req -new -key "${TMP_TLS_DIR}/server.key" -out "${TMP_TLS_DIR}/server.csr" -config "${TMP_TLS_DIR}/server.cnf"
openssl x509 -req -in "${TMP_TLS_DIR}/server.csr" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAserial "$CA_SERIAL" -CAcreateserial \
  -out "${TMP_TLS_DIR}/server.crt" -days 825 -sha256 \
  -extensions req_ext -extfile "${TMP_TLS_DIR}/server.cnf"

install -m 0644 "${TMP_TLS_DIR}/server.crt" "$SERVER_CERT"
install -m 0640 "${TMP_TLS_DIR}/server.key" "$SERVER_KEY"
chown root:root "$SERVER_CERT"
chown root:astrality "$SERVER_KEY"
chown astrality:astrality "$CA_CERT" "$CA_KEY"
chmod 640 "$CA_CERT"
chmod 600 "$CA_KEY"

cat > /etc/astrality/control-plane.env <<ENV
HTTP_ADDR=${CONTROL_ADDR}
DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}?sslmode=disable
DATA_DIR=${DATA_DIR}
BASTION_HOST=${BASTION_HOST}
CONSOLE_SSH_USER=${CONSOLE_SSH_USER}
CONSOLE_SSH_USERS=${CONSOLE_SSH_USERS}
CONSOLE_TARGET_ORDER=${CONSOLE_TARGET_ORDER}
CONSOLE_SSH_KEY_FILE=${CONSOLE_SSH_KEY_FILE}
TLS_CERT_FILE=${SERVER_CERT}
TLS_KEY_FILE=${SERVER_KEY}
OIDC_ISSUER=http://127.0.0.1:${KEYCLOAK_HTTP_PORT}/realms/astrality
OIDC_AUDIENCE=astrality-ui
DB_TIMEOUT_SEC=5
ENROLL_RATE_PER_MINUTE=30
LOGIN_RATE_PER_MINUTE=${LOGIN_RATE_PER_MINUTE}
HEARTBEAT_OFFLINE_SEC=60
ENV
chmod 600 /etc/astrality/control-plane.env
if [[ -n "${OIDC_CLIENT_SECRET}" ]]; then
  echo "OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}" >> /etc/astrality/control-plane.env
fi

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
Environment=KC_DB_PASSWORD=${KEYCLOAK_DB_PASS}
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

# Provision realm/client/roles/bootstrap-admin.
cat > /tmp/provision-keycloak.sh <<KCSH
#!/usr/bin/env bash
set -euo pipefail
KEYCLOAK_URL="http://127.0.0.1:${KEYCLOAK_HTTP_PORT}"
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
CLIENT_ID=\$(/opt/keycloak/bin/kcadm.sh get clients -r astrality -q clientId=astrality-ui --fields id | sed -n 's/.*"id" : "\\([^"]*\\)".*/\\1/p' | head -n1)
if ! /opt/keycloak/bin/kcadm.sh get clients/\${CLIENT_ID}/protocol-mappers/models -r astrality | grep -q '"name" : "roles"'; then
  /opt/keycloak/bin/kcadm.sh create clients/\${CLIENT_ID}/protocol-mappers/models -r astrality \
    -s name=roles \
    -s protocol=openid-connect \
    -s protocolMapper=oidc-usermodel-realm-role-mapper \
    -s 'config."multivalued"=true' \
    -s 'config."userinfo.token.claim"=true' \
    -s 'config."id.token.claim"=true' \
    -s 'config."access.token.claim"=true' \
    -s 'config."claim.name"=roles' \
    -s 'config."jsonType.label"=String'
fi
if ! /opt/keycloak/bin/kcadm.sh get users -r astrality -q username=${BOOTSTRAP_ADMIN_USER} | grep -q '"username" : "${BOOTSTRAP_ADMIN_USER}"'; then
  /opt/keycloak/bin/kcadm.sh create users -r astrality -s username=${BOOTSTRAP_ADMIN_USER} -s enabled=true
fi
USER_ID=\$(/opt/keycloak/bin/kcadm.sh get users -r astrality -q username=${BOOTSTRAP_ADMIN_USER} --fields id | sed -n 's/.*"id" : "\\([^"]*\\)".*/\\1/p' | head -n1)
/opt/keycloak/bin/kcadm.sh update users/\${USER_ID} -r astrality -s enabled=true -s emailVerified=true -s email=${BOOTSTRAP_ADMIN_USER}@astrality.local -s 'requiredActions=[]'
/opt/keycloak/bin/kcadm.sh set-password -r astrality --userid "\${USER_ID}" --new-password "${BOOTSTRAP_ADMIN_PASS}" --temporary=false
/opt/keycloak/bin/kcadm.sh add-roles -r astrality --uusername ${BOOTSTRAP_ADMIN_USER} --rolename admin
KCSH
chmod +x /tmp/provision-keycloak.sh

for _ in $(seq 1 60); do
  if curl -fsSL "http://127.0.0.1:${KEYCLOAK_HTTP_PORT}/realms/master/.well-known/openid-configuration" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
bash /tmp/provision-keycloak.sh

cat > /etc/astrality/bootstrap-admin.env <<ENV
OIDC_USERNAME=${BOOTSTRAP_ADMIN_USER}
OIDC_PASSWORD=${BOOTSTRAP_ADMIN_PASS}
OIDC_CLIENT_ID=astrality-ui
OIDC_TOKEN_URL=http://127.0.0.1:${KEYCLOAK_HTTP_PORT}/realms/astrality/protocol/openid-connect/token
ENV
if [[ -n "${OIDC_CLIENT_SECRET}" ]]; then
  echo "OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}" >> /etc/astrality/bootstrap-admin.env
fi
chmod 600 /etc/astrality/bootstrap-admin.env

# Prometheus target setup
cp "$ROOT_DIR/ops/prometheus.yml" /etc/prometheus/prometheus.yml
systemctl restart prometheus || true

systemctl enable --now astrality-control-plane

echo "setup complete"
echo "Control-plane: https://${DOMAIN}${CONTROL_ADDR}"
echo "Keycloak: http://127.0.0.1:${KEYCLOAK_HTTP_PORT}"
echo "Bootstrap admin creds: /etc/astrality/bootstrap-admin.env"
