# astrality

Centralized Linux node management control-plane with one-command enrollment.

## Features (V1)

- One-shot enrollment token API
- One-line node install script
- Agent heartbeat + hardware/software facts
- Node inventory API/UI
- Console session command generation via bastion SSH
- Basic log ingestion endpoint
- Agent credential rotation endpoint
- Node revocation endpoint
- v2 remote jobs queue (create/claim/result/cancel)
- v2 allowlist policy endpoint
- Prometheus metrics endpoint
- OIDC-ready auth (dev bearer fallback)
- mTLS between enrolled agents and control-plane (HTTPS mode)

## Repo layout

- `cmd/control-plane`: API server
- `cmd/agent`: node agent
- `internal/*`: shared modules
- `scripts/install.sh`: one-line node bootstrap target (signature/checksum aware)
- `scripts/setup-prod.sh`: production setup bootstrap (system services)
- `deploy/systemd`: service units
- `web`: minimal ops UI
- `ops`: monitoring configs

## Quick start (dev)

1. Start PostgreSQL and create DB `astrality`.
2. Run control-plane:

```bash
DEV_INSECURE_HTTP=true DATABASE_URL='postgres://astrality:astrality@127.0.0.1:5432/astrality?sslmode=disable' go run ./cmd/control-plane
```

3. Create an enrollment token:

```bash
curl -s -X POST http://127.0.0.1:8443/api/v1/enrollment-tokens \
  -H 'Authorization: Bearer dev-admin' \
  -H 'Content-Type: application/json' \
  -d '{"ttl_minutes":30}'
```

4. Build and host agent artifact:

```bash
make artifacts
```

5. Install on a node:

```bash
curl -fsSL http://127.0.0.1:8443/static/install.sh | sudo bash -s -- \
  --server http://127.0.0.1:8443 \
  --token <TOKEN> \
  --version latest
```

For production, run HTTPS with OIDC and keep `DEV_INSECURE_HTTP=false`.

## API summary

- `POST /api/v1/enrollment-tokens` (admin)
- `POST /api/v1/enroll`
- `POST /api/v1/agents/rotate`
- `POST /api/v1/heartbeat` (agent)
- `POST /api/v1/facts` (agent)
- `POST /api/v1/logs` (agent)
- `GET /api/v1/nodes` (viewer)
- `GET /api/v1/nodes/{id}` (viewer)
- `GET /api/v1/nodes/{id}/heartbeats` (viewer)
- `GET /api/v1/nodes/{id}/logs` (viewer)
- `POST /api/v1/nodes/{id}/console/session` (operator)
- `POST /api/v1/nodes/{id}/revoke` (admin)

## API v2 (jobs)

- `GET /api/v2/jobs` (viewer)
- `POST /api/v2/jobs` (operator)
- `GET /api/v2/jobs/{id}` (viewer)
- `GET /api/v2/jobs/{id}/runs` (viewer)
- `POST /api/v2/jobs/{id}/cancel` (operator)
- `GET /api/v2/policies/allowlist` (viewer)
- `PUT /api/v2/policies/allowlist` (admin)
- `POST /api/v2/agent/jobs/next` (agent)
- `POST /api/v2/agent/jobs/{run_id}/result` (agent)

## Dev bearer tokens

- `dev-admin`
- `dev-operator`
- `dev-viewer`

## Notes

- Enrollment endpoint accepts bootstrap HTTPS without client cert; post-enrollment endpoints require mTLS in HTTPS mode.
- Agent stores cert/key/state in `/etc/astrality` by default.
- Enroll token rate limiting is enabled (`ENROLL_RATE_PER_MINUTE`).
- Agent removes `ENROLL_TOKEN` from `agent.env` after first successful enrollment.

## Production bootstrap (mono-site)

```bash
sudo DB_PASS='change-me' KEYCLOAK_ADMIN_PASS='change-me' ./scripts/setup-prod.sh
```

The script installs PostgreSQL, control-plane service, Keycloak service, and Prometheus baseline config.
