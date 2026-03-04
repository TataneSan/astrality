package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool *pgxpool.Pool
}

type Node struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	IP           string    `json:"ip"`
	Version      string    `json:"version"`
	Status       string    `json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	CreatedAt    time.Time `json:"created_at"`
	CPUUsage     float64   `json:"cpu_usage"`
	MemUsage     float64   `json:"mem_usage"`
	DiskUsage    float64   `json:"disk_usage"`
	Load1        float64   `json:"load1"`
	UptimeSec    int64     `json:"uptime_sec"`
	AgentVersion string    `json:"agent_version"`
}

type NodeFact struct {
	NodeID       string    `json:"node_id"`
	Kernel       string    `json:"kernel"`
	CPUModel     string    `json:"cpu_model"`
	CPUCores     int       `json:"cpu_cores"`
	MemTotalMB   int64     `json:"mem_total_mb"`
	DiskTotalGB  int64     `json:"disk_total_gb"`
	AgentVersion string    `json:"agent_version"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Heartbeat struct {
	NodeID    string    `json:"node_id"`
	CPUUsage  float64   `json:"cpu_usage"`
	MemUsage  float64   `json:"mem_usage"`
	DiskUsage float64   `json:"disk_usage"`
	Load1     float64   `json:"load1"`
	UptimeSec int64     `json:"uptime_sec"`
	TS        time.Time `json:"ts"`
}

type LogEntry struct {
	NodeID  string    `json:"node_id"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	TS      time.Time `json:"ts"`
}

func Connect(ctx context.Context, dbURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, fmt.Errorf("connect db: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() {
	s.Pool.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS enrollment_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			token_hash TEXT UNIQUE NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id UUID PRIMARY KEY,
			hostname TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			ip TEXT NOT NULL,
			version TEXT NOT NULL,
			status TEXT NOT NULL,
			last_seen TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS node_auth (
			node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
			token_hash TEXT UNIQUE NOT NULL,
			revoked_at TIMESTAMPTZ,
			rotated_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE node_auth ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`,
		`ALTER TABLE node_auth ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ`,
		`CREATE TABLE IF NOT EXISTS heartbeats (
			id BIGSERIAL PRIMARY KEY,
			node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			cpu_usage DOUBLE PRECISION NOT NULL,
			mem_usage DOUBLE PRECISION NOT NULL,
			disk_usage DOUBLE PRECISION NOT NULL,
			load1 DOUBLE PRECISION NOT NULL,
			uptime_sec BIGINT NOT NULL,
			ts TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_heartbeats_node_ts ON heartbeats(node_id, ts DESC)`,
		`CREATE TABLE IF NOT EXISTS node_facts (
			node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
			kernel TEXT NOT NULL,
			cpu_model TEXT NOT NULL,
			cpu_cores INT NOT NULL,
			mem_total_mb BIGINT NOT NULL,
			disk_total_gb BIGINT NOT NULL,
			agent_version TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id BIGSERIAL PRIMARY KEY,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			node_id UUID,
			details JSONB NOT NULL DEFAULT '{}'::jsonb,
			ts TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts DESC)`,
		`CREATE TABLE IF NOT EXISTS ssh_sessions (
			id UUID PRIMARY KEY,
			node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			requested_by TEXT NOT NULL,
			command TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS logs (
			id BIGSERIAL PRIMARY KEY,
			node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			level TEXT NOT NULL,
			message TEXT NOT NULL,
			ts TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_node_ts ON logs(node_id, ts DESC)`,
		`CREATE TABLE IF NOT EXISTS jobs (
			id UUID PRIMARY KEY,
			node_selector TEXT NOT NULL,
			command TEXT NOT NULL,
			args JSONB NOT NULL DEFAULT '[]'::jsonb,
			timeout_sec INT NOT NULL,
			max_retries INT NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			canceled_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS job_runs (
			id UUID PRIMARY KEY,
			job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
			node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			status TEXT NOT NULL,
			attempt INT NOT NULL DEFAULT 0,
			exit_code INT,
			stdout TEXT NOT NULL DEFAULT '',
			stderr TEXT NOT NULL DEFAULT '',
			started_at TIMESTAMPTZ,
			finished_at TIMESTAMPTZ,
			claimed_by TEXT,
			claim_expires_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(job_id, node_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_runs_node_status ON job_runs(node_id, status, updated_at)`,
		`CREATE INDEX IF NOT EXISTS idx_job_runs_job ON job_runs(job_id, updated_at)`,
		`CREATE TABLE IF NOT EXISTS allowlist_policies (
			id INT PRIMARY KEY,
			commands TEXT[] NOT NULL,
			updated_by TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`INSERT INTO allowlist_policies(id, commands, updated_by)
		   VALUES(1, ARRAY['uname','uptime','df','free','echo','cat','ls','systemctl','journalctl']::text[], 'system')
		   ON CONFLICT (id) DO NOTHING`,
	}

	for _, stmt := range stmts {
		if _, err := s.Pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}
	return nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, tokenHash string, expiresAt time.Time, createdBy string) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO enrollment_tokens(token_hash, expires_at, created_by) VALUES($1,$2,$3)`,
		tokenHash, expiresAt, createdBy,
	)
	return err
}

func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tokenHash string) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx,
		`SELECT expires_at, used_at FROM enrollment_tokens WHERE token_hash=$1 FOR UPDATE`, tokenHash,
	).Scan(&expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("invalid token")
		}
		return err
	}
	if usedAt != nil {
		return fmt.Errorf("token already used")
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("token expired")
	}
	if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET used_at=now() WHERE token_hash=$1`, tokenHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RegisterNode(ctx context.Context, id, hostname, osName, arch, ip, version, authTokenHash string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO nodes(id,hostname,os,arch,ip,version,status,last_seen)
		VALUES($1,$2,$3,$4,$5,$6,'online',now())
	`, id, hostname, osName, arch, ip, version)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO node_auth(node_id, token_hash) VALUES($1,$2)`,
		id, authTokenHash,
	)
	return err
}

func (s *Store) ResolveNodeByAuthToken(ctx context.Context, token string) (string, error) {
	var nodeID string
	err := s.Pool.QueryRow(ctx,
		`SELECT node_id::text FROM node_auth WHERE token_hash=$1 AND revoked_at IS NULL`, HashToken(token),
	).Scan(&nodeID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("invalid agent token")
		}
		return "", err
	}
	return nodeID, nil
}

func (s *Store) InsertHeartbeat(ctx context.Context, hb Heartbeat) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO heartbeats(node_id,cpu_usage,mem_usage,disk_usage,load1,uptime_sec,ts)
		VALUES($1,$2,$3,$4,$5,$6,$7)
	`, hb.NodeID, hb.CPUUsage, hb.MemUsage, hb.DiskUsage, hb.Load1, hb.UptimeSec, hb.TS)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `
		UPDATE nodes
		SET status='online', last_seen=$2, updated_at=now()
		WHERE id=$1 AND status <> 'revoked'
	`, hb.NodeID, hb.TS)
	return err
}

func (s *Store) UpsertFacts(ctx context.Context, nf NodeFact) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO node_facts(node_id,kernel,cpu_model,cpu_cores,mem_total_mb,disk_total_gb,agent_version,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,now())
		ON CONFLICT(node_id) DO UPDATE SET
			kernel=EXCLUDED.kernel,
			cpu_model=EXCLUDED.cpu_model,
			cpu_cores=EXCLUDED.cpu_cores,
			mem_total_mb=EXCLUDED.mem_total_mb,
			disk_total_gb=EXCLUDED.disk_total_gb,
			agent_version=EXCLUDED.agent_version,
			updated_at=now()
	`, nf.NodeID, nf.Kernel, nf.CPUModel, nf.CPUCores, nf.MemTotalMB, nf.DiskTotalGB, nf.AgentVersion)
	return err
}

func (s *Store) ListNodes(ctx context.Context, offlineAfter time.Duration) ([]Node, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT n.id::text, n.hostname, n.os, n.arch, n.ip, n.version, n.status, n.last_seen, n.created_at,
		       COALESCE(h.cpu_usage,0), COALESCE(h.mem_usage,0), COALESCE(h.disk_usage,0), COALESCE(h.load1,0), COALESCE(h.uptime_sec,0),
		       COALESCE(f.agent_version,'')
		FROM nodes n
		LEFT JOIN LATERAL (
			SELECT cpu_usage, mem_usage, disk_usage, load1, uptime_sec
			FROM heartbeats
			WHERE node_id=n.id
			ORDER BY ts DESC
			LIMIT 1
		) h ON true
		LEFT JOIN node_facts f ON f.node_id=n.id
		ORDER BY n.hostname ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make([]Node, 0)
	now := time.Now()
	for rows.Next() {
		var n Node
		if err := rows.Scan(
			&n.ID, &n.Hostname, &n.OS, &n.Arch, &n.IP, &n.Version, &n.Status, &n.LastSeen, &n.CreatedAt,
			&n.CPUUsage, &n.MemUsage, &n.DiskUsage, &n.Load1, &n.UptimeSec, &n.AgentVersion,
		); err != nil {
			return nil, err
		}
		n.Status = computeStatus(n.Status, n.LastSeen, now, offlineAfter)
		res = append(res, n)
	}
	return res, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id string, offlineAfter time.Duration) (Node, NodeFact, error) {
	var n Node
	err := s.Pool.QueryRow(ctx, `
		SELECT n.id::text, n.hostname, n.os, n.arch, n.ip, n.version, n.status, n.last_seen, n.created_at,
		       COALESCE(h.cpu_usage,0), COALESCE(h.mem_usage,0), COALESCE(h.disk_usage,0), COALESCE(h.load1,0), COALESCE(h.uptime_sec,0),
		       COALESCE(f.agent_version,'')
		FROM nodes n
		LEFT JOIN LATERAL (
			SELECT cpu_usage, mem_usage, disk_usage, load1, uptime_sec
			FROM heartbeats
			WHERE node_id=n.id
			ORDER BY ts DESC
			LIMIT 1
		) h ON true
		LEFT JOIN node_facts f ON f.node_id=n.id
		WHERE n.id=$1
	`, id).Scan(
		&n.ID, &n.Hostname, &n.OS, &n.Arch, &n.IP, &n.Version, &n.Status, &n.LastSeen, &n.CreatedAt,
		&n.CPUUsage, &n.MemUsage, &n.DiskUsage, &n.Load1, &n.UptimeSec, &n.AgentVersion,
	)
	if err != nil {
		return Node{}, NodeFact{}, err
	}
	n.Status = computeStatus(n.Status, n.LastSeen, time.Now(), offlineAfter)

	var f NodeFact
	err = s.Pool.QueryRow(ctx, `
		SELECT node_id::text, kernel, cpu_model, cpu_cores, mem_total_mb, disk_total_gb, agent_version, updated_at
		FROM node_facts WHERE node_id=$1
	`, id).Scan(&f.NodeID, &f.Kernel, &f.CPUModel, &f.CPUCores, &f.MemTotalMB, &f.DiskTotalGB, &f.AgentVersion, &f.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return n, NodeFact{}, nil
		}
		return Node{}, NodeFact{}, err
	}
	return n, f, nil
}

func (s *Store) ListHeartbeats(ctx context.Context, nodeID string, limit int) ([]Heartbeat, error) {
	if limit <= 0 || limit > 500 {
		limit = 120
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT node_id::text, cpu_usage, mem_usage, disk_usage, load1, uptime_sec, ts
		FROM heartbeats
		WHERE node_id=$1
		ORDER BY ts DESC
		LIMIT $2
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := make([]Heartbeat, 0)
	for rows.Next() {
		var hb Heartbeat
		if err := rows.Scan(&hb.NodeID, &hb.CPUUsage, &hb.MemUsage, &hb.DiskUsage, &hb.Load1, &hb.UptimeSec, &hb.TS); err != nil {
			return nil, err
		}
		res = append(res, hb)
	}
	return res, rows.Err()
}

func (s *Store) InsertAudit(ctx context.Context, actor, action, nodeID string, details map[string]any) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_events(actor, action, node_id, details) VALUES($1,$2,NULLIF($3,''),$4)`,
		actor, action, nodeID, details,
	)
	return err
}

func (s *Store) InsertSSHSession(ctx context.Context, id, nodeID, requestedBy, command string, expiresAt time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO ssh_sessions(id,node_id,requested_by,command,expires_at)
		VALUES($1,$2,$3,$4,$5)
	`, id, nodeID, requestedBy, command, expiresAt)
	return err
}

func (s *Store) InsertLog(ctx context.Context, l LogEntry) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO logs(node_id, level, message, ts) VALUES($1,$2,$3,$4)`,
		l.NodeID, l.Level, l.Message, l.TS,
	)
	return err
}

func (s *Store) ListLogs(ctx context.Context, nodeID string, limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT node_id::text, level, message, ts
		FROM logs
		WHERE node_id=$1
		ORDER BY ts DESC
		LIMIT $2
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := make([]LogEntry, 0)
	for rows.Next() {
		var l LogEntry
		if err := rows.Scan(&l.NodeID, &l.Level, &l.Message, &l.TS); err != nil {
			return nil, err
		}
		res = append(res, l)
	}
	return res, rows.Err()
}

func (s *Store) CountNodes(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&n)
	return n, err
}

func (s *Store) RotateNodeAuthToken(ctx context.Context, nodeID, oldTokenHash, newTokenHash string) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE node_auth
		SET token_hash=$3, rotated_at=now()
		WHERE node_id=$1 AND token_hash=$2 AND revoked_at IS NULL
	`, nodeID, oldTokenHash, newTokenHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("token rotation failed")
	}
	return nil
}

func (s *Store) RevokeNode(ctx context.Context, nodeID string) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE node_auth
		SET revoked_at=now()
		WHERE node_id=$1
	`, nodeID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE nodes
		SET status='revoked', updated_at=now()
		WHERE id=$1
	`, nodeID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func computeStatus(base string, lastSeen, now time.Time, offlineAfter time.Duration) string {
	if base == "revoked" {
		return "revoked"
	}
	if offlineAfter <= 0 {
		offlineAfter = 60 * time.Second
	}
	if now.Sub(lastSeen) > offlineAfter {
		return "offline"
	}
	if now.Sub(lastSeen) > offlineAfter/2 {
		return "degraded"
	}
	return "online"
}
