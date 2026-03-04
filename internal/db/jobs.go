package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Job struct {
	ID           string    `json:"id"`
	NodeSelector string    `json:"node_selector"`
	Command      string    `json:"command"`
	Args         []string  `json:"args"`
	TimeoutSec   int       `json:"timeout_sec"`
	MaxRetries   int       `json:"max_retries"`
	Status       string    `json:"status"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type JobRun struct {
	ID         string     `json:"id"`
	JobID      string     `json:"job_id"`
	NodeID     string     `json:"node_id"`
	Status     string     `json:"status"`
	Attempt    int        `json:"attempt"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Stdout     string     `json:"stdout"`
	Stderr     string     `json:"stderr"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type JobTask struct {
	RunID      string   `json:"run_id"`
	JobID      string   `json:"job_id"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	TimeoutSec int      `json:"timeout_sec"`
	Attempt    int      `json:"attempt"`
	MaxRetries int      `json:"max_retries"`
}

type AllowlistPolicy struct {
	Commands  []string  `json:"commands"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Store) GetAllowlistPolicy(ctx context.Context) (AllowlistPolicy, error) {
	var p AllowlistPolicy
	err := s.Pool.QueryRow(ctx, `
		SELECT commands, updated_by, updated_at
		FROM allowlist_policies
		WHERE id=1
	`).Scan(&p.Commands, &p.UpdatedBy, &p.UpdatedAt)
	if err != nil {
		return AllowlistPolicy{}, err
	}
	return p, nil
}

func (s *Store) UpdateAllowlistPolicy(ctx context.Context, commands []string, updatedBy string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO allowlist_policies(id, commands, updated_by, updated_at)
		VALUES(1,$1,$2,now())
		ON CONFLICT(id) DO UPDATE SET commands=EXCLUDED.commands, updated_by=EXCLUDED.updated_by, updated_at=now()
	`, commands, updatedBy)
	return err
}

func (s *Store) CreateJob(ctx context.Context, nodeSelector, command string, args []string, timeoutSec, maxRetries int, createdBy string) (Job, error) {
	nodes, err := s.resolveNodesForSelector(ctx, nodeSelector)
	if err != nil {
		return Job{}, err
	}
	if len(nodes) == 0 {
		return Job{}, fmt.Errorf("selector matched no nodes")
	}
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	if maxRetries < 0 {
		maxRetries = 0
	}

	argsJSON, _ := json.Marshal(args)
	jobID := uuid.NewString()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO jobs(id, node_selector, command, args, timeout_sec, max_retries, status, created_by)
		VALUES($1,$2,$3,$4,$5,$6,'queued',$7)
	`, jobID, nodeSelector, command, argsJSON, timeoutSec, maxRetries, createdBy)
	if err != nil {
		return Job{}, err
	}

	for _, nodeID := range nodes {
		_, err := tx.Exec(ctx, `
			INSERT INTO job_runs(id, job_id, node_id, status)
			VALUES($1,$2,$3,'queued')
		`, uuid.NewString(), jobID, nodeID)
		if err != nil {
			return Job{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Job{}, err
	}

	return Job{
		ID:           jobID,
		NodeSelector: nodeSelector,
		Command:      command,
		Args:         args,
		TimeoutSec:   timeoutSec,
		MaxRetries:   maxRetries,
		Status:       "queued",
		CreatedBy:    createdBy,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}, nil
}

func (s *Store) ListJobs(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, node_selector, command, args, timeout_sec, max_retries, status, created_by, created_at, updated_at
		FROM jobs
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Job, 0)
	for rows.Next() {
		var j Job
		var argsJSON []byte
		if err := rows.Scan(&j.ID, &j.NodeSelector, &j.Command, &argsJSON, &j.TimeoutSec, &j.MaxRetries, &j.Status, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(argsJSON, &j.Args)
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) GetJob(ctx context.Context, jobID string) (Job, []JobRun, error) {
	var j Job
	var argsJSON []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, node_selector, command, args, timeout_sec, max_retries, status, created_by, created_at, updated_at
		FROM jobs
		WHERE id=$1
	`, jobID).Scan(&j.ID, &j.NodeSelector, &j.Command, &argsJSON, &j.TimeoutSec, &j.MaxRetries, &j.Status, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return Job{}, nil, err
	}
	_ = json.Unmarshal(argsJSON, &j.Args)

	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, job_id::text, node_id::text, status, attempt, exit_code, stdout, stderr, started_at, finished_at, updated_at
		FROM job_runs
		WHERE job_id=$1
		ORDER BY updated_at DESC
	`, jobID)
	if err != nil {
		return Job{}, nil, err
	}
	defer rows.Close()
	runs := make([]JobRun, 0)
	for rows.Next() {
		var r JobRun
		if err := rows.Scan(&r.ID, &r.JobID, &r.NodeID, &r.Status, &r.Attempt, &r.ExitCode, &r.Stdout, &r.Stderr, &r.StartedAt, &r.FinishedAt, &r.UpdatedAt); err != nil {
			return Job{}, nil, err
		}
		runs = append(runs, r)
	}
	return j, runs, rows.Err()
}

func (s *Store) CancelJob(ctx context.Context, jobID string) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE jobs
		SET status='canceled', canceled_at=now(), updated_at=now()
		WHERE id=$1
	`, jobID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE job_runs
		SET status='canceled', finished_at=now(), updated_at=now()
		WHERE job_id=$1 AND status IN ('queued','claimed','running')
	`, jobID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ClaimNextJobRun(ctx context.Context, nodeID string) (JobTask, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return JobTask{}, err
	}
	defer tx.Rollback(ctx)

	var runID string
	var jobID string
	var command string
	var argsJSON []byte
	var timeoutSec int
	var attempt int
	var maxRetries int
	err = tx.QueryRow(ctx, `
		SELECT jr.id::text, j.id::text, j.command, j.args, j.timeout_sec, jr.attempt, j.max_retries
		FROM job_runs jr
		JOIN jobs j ON j.id=jr.job_id
		WHERE jr.node_id=$1
		  AND (
			jr.status='queued'
			OR (jr.status='claimed' AND jr.claim_expires_at < now())
		  )
		  AND j.status IN ('queued','running')
		ORDER BY jr.updated_at ASC
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`, nodeID).Scan(&runID, &jobID, &command, &argsJSON, &timeoutSec, &attempt, &maxRetries)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return JobTask{}, pgx.ErrNoRows
		}
		return JobTask{}, err
	}

	attempt++
	_, err = tx.Exec(ctx, `
		UPDATE job_runs
		SET status='claimed',
			attempt=$2,
			claimed_by=$3,
			claim_expires_at=now() + interval '45 seconds',
			started_at=COALESCE(started_at, now()),
			updated_at=now()
		WHERE id=$1
	`, runID, attempt, nodeID)
	if err != nil {
		return JobTask{}, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE jobs
		SET status='running', updated_at=now()
		WHERE id=$1 AND status='queued'
	`, jobID)
	if err != nil {
		return JobTask{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return JobTask{}, err
	}

	var args []string
	_ = json.Unmarshal(argsJSON, &args)
	return JobTask{
		RunID:      runID,
		JobID:      jobID,
		Command:    command,
		Args:       args,
		TimeoutSec: timeoutSec,
		Attempt:    attempt,
		MaxRetries: maxRetries,
	}, nil
}

func (s *Store) CompleteJobRun(ctx context.Context, nodeID, runID, status string, exitCode int, stdout, stderr string, startedAt, finishedAt time.Time) error {
	if len(stdout) > 100000 {
		stdout = stdout[:100000]
	}
	if len(stderr) > 100000 {
		stderr = stderr[:100000]
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var jobID string
	var attempt int
	var maxRetries int
	err = tx.QueryRow(ctx, `
		SELECT jr.job_id::text, jr.attempt, j.max_retries
		FROM job_runs jr
		JOIN jobs j ON j.id=jr.job_id
		WHERE jr.id=$1 AND jr.node_id=$2
		FOR UPDATE
	`, runID, nodeID).Scan(&jobID, &attempt, &maxRetries)
	if err != nil {
		return err
	}

	finalStatus := status
	if (status == "failed" || status == "timed_out") && attempt <= maxRetries {
		finalStatus = "queued"
	}

	if finalStatus == "queued" {
		_, err = tx.Exec(ctx, `
			UPDATE job_runs
			SET status='queued',
				claim_expires_at=NULL,
				claimed_by=NULL,
				updated_at=now(),
				stderr=$2,
				stdout=$3
			WHERE id=$1
		`, runID, stderr, stdout)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE job_runs
			SET status=$2,
				exit_code=$3,
				stdout=$4,
				stderr=$5,
				started_at=COALESCE(started_at, $6),
				finished_at=$7,
				updated_at=now()
			WHERE id=$1
		`, runID, finalStatus, exitCode, stdout, stderr, startedAt, finishedAt)
	}
	if err != nil {
		return err
	}

	jobStatus, err := recomputeJobStatus(ctx, tx, jobID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE jobs SET status=$2, updated_at=now() WHERE id=$1`, jobID, jobStatus)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func recomputeJobStatus(ctx context.Context, tx pgx.Tx, jobID string) (string, error) {
	var queued, claimed, running, failed, timedOut, canceled, succeeded, total int
	err := tx.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status='queued'),
			COUNT(*) FILTER (WHERE status='claimed'),
			COUNT(*) FILTER (WHERE status='running'),
			COUNT(*) FILTER (WHERE status='failed'),
			COUNT(*) FILTER (WHERE status='timed_out'),
			COUNT(*) FILTER (WHERE status='canceled'),
			COUNT(*) FILTER (WHERE status='succeeded'),
			COUNT(*)
		FROM job_runs
		WHERE job_id=$1
	`, jobID).Scan(&queued, &claimed, &running, &failed, &timedOut, &canceled, &succeeded, &total)
	if err != nil {
		return "", err
	}
	if running > 0 || claimed > 0 {
		return "running", nil
	}
	if queued > 0 {
		return "queued", nil
	}
	if failed > 0 || timedOut > 0 {
		return "failed", nil
	}
	if canceled == total {
		return "canceled", nil
	}
	if succeeded == total {
		return "succeeded", nil
	}
	return "failed", nil
}

func (s *Store) resolveNodesForSelector(ctx context.Context, selector string) ([]string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" || selector == "all" {
		rows, err := s.Pool.Query(ctx, `SELECT id::text FROM nodes WHERE status <> 'revoked' ORDER BY created_at ASC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := make([]string, 0)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, id)
		}
		return out, rows.Err()
	}

	parts := strings.Split(selector, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		id := strings.TrimSpace(p)
		if id == "" {
			continue
		}
		var exists string
		err := s.Pool.QueryRow(ctx, `SELECT id::text FROM nodes WHERE id=$1 AND status <> 'revoked'`, id).Scan(&exists)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return nil, err
		}
		out = append(out, exists)
	}
	return out, nil
}
