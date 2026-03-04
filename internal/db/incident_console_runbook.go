package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ConsoleSession struct {
	ID        string     `json:"id"`
	NodeID    string     `json:"node_id"`
	OpenedBy  string     `json:"opened_by"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
}

type ConsoleFrame struct {
	ID         int64     `json:"id"`
	SessionID  string    `json:"session_id"`
	TS         time.Time `json:"ts"`
	Stream     string    `json:"stream"`
	PayloadB64 string    `json:"payload_b64"`
}

type TimelineEvent struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	NodeID   string         `json:"node_id,omitempty"`
	Severity string         `json:"severity"`
	Actor    string         `json:"actor"`
	Message  string         `json:"message"`
	Refs     map[string]any `json:"refs"`
	TS       time.Time      `json:"ts"`
}

type RunbookTemplate struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	TriggerTags []string         `json:"trigger_tags"`
	Steps       []RunbookStepDef `json:"steps"`
	CreatedAt   time.Time        `json:"created_at"`
}

type RunbookStepDef struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Kind    string `json:"kind"`
	Command string `json:"command,omitempty"`
}

type RunbookExecution struct {
	ID          string                 `json:"id"`
	RunbookID   string                 `json:"runbook_id"`
	IncidentID  string                 `json:"incident_id,omitempty"`
	Status      string                 `json:"status"`
	CurrentStep int                    `json:"current_step"`
	StartedBy   string                 `json:"started_by"`
	StartedAt   time.Time              `json:"started_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Steps       []RunbookExecutionStep `json:"steps,omitempty"`
}

type RunbookExecutionStep struct {
	ID          string     `json:"id"`
	ExecutionID string     `json:"execution_id"`
	StepID      string     `json:"step_id"`
	Status      string     `json:"status"`
	Output      string     `json:"output"`
	ConfirmedBy string     `json:"confirmed_by,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

func (s *Store) CreateConsoleSession(ctx context.Context, nodeID, openedBy, reason, tokenHash string, expiresAt time.Time) (ConsoleSession, error) {
	var out ConsoleSession
	out.ID = uuid.NewString()
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO console_sessions(id,node_id,opened_by,reason,status,session_token_hash,expires_at)
		VALUES($1,$2,$3,$4,'opening',$5,$6)
		RETURNING node_id::text, opened_by, reason, status, started_at, ended_at, expires_at
	`, out.ID, nodeID, openedBy, reason, tokenHash, expiresAt).Scan(&out.NodeID, &out.OpenedBy, &out.Reason, &out.Status, &out.StartedAt, &out.EndedAt, &out.ExpiresAt)
	if err != nil {
		return ConsoleSession{}, err
	}
	return out, nil
}

func (s *Store) MarkConsoleSessionActive(ctx context.Context, sessionID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE console_sessions SET status='active' WHERE id=$1`, sessionID)
	return err
}

func (s *Store) CloseConsoleSession(ctx context.Context, sessionID string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE console_sessions
		SET status='closed', ended_at=now()
		WHERE id=$1 AND status <> 'closed'
	`, sessionID)
	return err
}

func (s *Store) ValidateConsoleSessionToken(ctx context.Context, sessionID, tokenHash string) (ConsoleSession, error) {
	var out ConsoleSession
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, node_id::text, opened_by, reason, status, started_at, ended_at, expires_at
		FROM console_sessions
		WHERE id=$1 AND session_token_hash=$2 AND expires_at > now() AND status IN ('opening','active')
	`, sessionID, tokenHash).Scan(&out.ID, &out.NodeID, &out.OpenedBy, &out.Reason, &out.Status, &out.StartedAt, &out.EndedAt, &out.ExpiresAt)
	if err != nil {
		return ConsoleSession{}, err
	}
	return out, nil
}

func (s *Store) GetConsoleSession(ctx context.Context, sessionID string) (ConsoleSession, error) {
	var out ConsoleSession
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, node_id::text, opened_by, reason, status, started_at, ended_at, expires_at
		FROM console_sessions WHERE id=$1
	`, sessionID).Scan(&out.ID, &out.NodeID, &out.OpenedBy, &out.Reason, &out.Status, &out.StartedAt, &out.EndedAt, &out.ExpiresAt)
	if err != nil {
		return ConsoleSession{}, err
	}
	return out, nil
}

func (s *Store) ListConsoleSessions(ctx context.Context, limit int) ([]ConsoleSession, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, node_id::text, opened_by, reason, status, started_at, ended_at, expires_at
		FROM console_sessions
		ORDER BY started_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ConsoleSession, 0)
	for rows.Next() {
		var c ConsoleSession
		if err := rows.Scan(&c.ID, &c.NodeID, &c.OpenedBy, &c.Reason, &c.Status, &c.StartedAt, &c.EndedAt, &c.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) AppendConsoleFrame(ctx context.Context, sessionID, stream, payloadB64 string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO console_frames(session_id, stream, payload_b64)
		VALUES($1,$2,$3)
	`, sessionID, stream, payloadB64)
	return err
}

func (s *Store) ListConsoleReplay(ctx context.Context, sessionID string, offset, limit int) ([]ConsoleFrame, bool, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, session_id::text, ts, stream, payload_b64
		FROM console_frames
		WHERE session_id=$1
		ORDER BY id ASC
		OFFSET $2 LIMIT $3
	`, sessionID, offset, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]ConsoleFrame, 0)
	for rows.Next() {
		var f ConsoleFrame
		if err := rows.Scan(&f.ID, &f.SessionID, &f.TS, &f.Stream, &f.PayloadB64); err != nil {
			return nil, false, err
		}
		out = append(out, f)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, rows.Err()
}

func (s *Store) InsertTimelineEvent(ctx context.Context, kind, nodeID, severity, actor, message string, refs map[string]any) error {
	if severity == "" {
		severity = "info"
	}
	if refs == nil {
		refs = map[string]any{}
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO incident_timeline(id, kind, node_id, severity, actor, message, refs)
		VALUES($1,$2,NULLIF($3,'')::uuid,$4,$5,$6,$7)
	`, uuid.NewString(), kind, nodeID, severity, actor, truncateText(message, 2000), refs)
	return err
}

func (s *Store) ListTimelineEvents(ctx context.Context, nodeID, severity string, from, to *time.Time, limit int) ([]TimelineEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var fromV time.Time
	var toV time.Time
	if from == nil {
		fromV = time.Unix(0, 0)
	} else {
		fromV = *from
	}
	if to == nil {
		toV = time.Now().Add(24 * time.Hour)
	} else {
		toV = *to
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, kind, COALESCE(node_id::text,''), severity, actor, message, refs, ts
		FROM incident_timeline
		WHERE ($1='' OR node_id=$1::uuid)
		  AND ($2='' OR severity=$2)
		  AND ts >= $3 AND ts <= $4
		ORDER BY ts DESC
		LIMIT $5
	`, strings.TrimSpace(nodeID), strings.TrimSpace(severity), fromV, toV, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TimelineEvent, 0)
	for rows.Next() {
		var t TimelineEvent
		var refs []byte
		if err := rows.Scan(&t.ID, &t.Kind, &t.NodeID, &t.Severity, &t.Actor, &t.Message, &refs, &t.TS); err != nil {
			return nil, err
		}
		t.Refs = map[string]any{}
		_ = json.Unmarshal(refs, &t.Refs)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListRunbookTemplates(ctx context.Context) ([]RunbookTemplate, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, name, trigger_tags, steps, created_at
		FROM runbook_templates
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RunbookTemplate, 0)
	for rows.Next() {
		var r RunbookTemplate
		var steps []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.TriggerTags, &steps, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(steps, &r.Steps)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateRunbookTemplate(ctx context.Context, r RunbookTemplate) (RunbookTemplate, error) {
	if strings.TrimSpace(r.Name) == "" {
		return RunbookTemplate{}, fmt.Errorf("name required")
	}
	r.ID = uuid.NewString()
	steps, _ := json.Marshal(r.Steps)
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO runbook_templates(id,name,trigger_tags,steps)
		VALUES($1,$2,$3,$4)
		RETURNING created_at
	`, r.ID, r.Name, r.TriggerTags, steps).Scan(&r.CreatedAt)
	if err != nil {
		return RunbookTemplate{}, err
	}
	return r, nil
}

func (s *Store) StartRunbookExecution(ctx context.Context, runbookID, incidentID, startedBy string) (RunbookExecution, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RunbookExecution{}, err
	}
	defer tx.Rollback(ctx)

	var tmpl RunbookTemplate
	var stepsJSON []byte
	err = tx.QueryRow(ctx, `SELECT id::text, name, trigger_tags, steps, created_at FROM runbook_templates WHERE id=$1`, runbookID).Scan(&tmpl.ID, &tmpl.Name, &tmpl.TriggerTags, &stepsJSON, &tmpl.CreatedAt)
	if err != nil {
		return RunbookExecution{}, err
	}
	_ = json.Unmarshal(stepsJSON, &tmpl.Steps)

	exec := RunbookExecution{ID: uuid.NewString(), RunbookID: runbookID, IncidentID: incidentID, Status: "running", CurrentStep: 0, StartedBy: startedBy}
	err = tx.QueryRow(ctx, `
		INSERT INTO runbook_executions(id,runbook_id,incident_id,status,current_step,started_by)
		VALUES($1,$2,NULLIF($3,''),$4,$5,$6)
		RETURNING started_at, updated_at
	`, exec.ID, exec.RunbookID, exec.IncidentID, exec.Status, exec.CurrentStep, exec.StartedBy).Scan(&exec.StartedAt, &exec.UpdatedAt)
	if err != nil {
		return RunbookExecution{}, err
	}
	for _, sdef := range tmpl.Steps {
		_, err := tx.Exec(ctx, `
			INSERT INTO runbook_execution_steps(id,execution_id,step_id,status)
			VALUES($1,$2,$3,'pending')
		`, uuid.NewString(), exec.ID, sdef.ID)
		if err != nil {
			return RunbookExecution{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return RunbookExecution{}, err
	}
	return exec, nil
}

func (s *Store) ConfirmRunbookStep(ctx context.Context, executionID, stepID, actor string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE runbook_execution_steps
		SET status='confirmed', confirmed_by=$3, confirmed_at=now()
		WHERE execution_id=$1 AND step_id=$2
	`, executionID, stepID, actor)
	if err != nil {
		return err
	}

	var remaining int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM runbook_execution_steps
		WHERE execution_id=$1 AND status <> 'confirmed'
	`, executionID).Scan(&remaining)
	if err != nil {
		return err
	}
	status := "running"
	if remaining == 0 {
		status = "completed"
	}
	_, err = tx.Exec(ctx, `UPDATE runbook_executions SET status=$2, updated_at=now() WHERE id=$1`, executionID, status)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetRunbookExecution(ctx context.Context, executionID string) (RunbookExecution, error) {
	var e RunbookExecution
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, runbook_id::text, COALESCE(incident_id::text,''), status, current_step, started_by, started_at, updated_at
		FROM runbook_executions
		WHERE id=$1
	`, executionID).Scan(&e.ID, &e.RunbookID, &e.IncidentID, &e.Status, &e.CurrentStep, &e.StartedBy, &e.StartedAt, &e.UpdatedAt)
	if err != nil {
		return RunbookExecution{}, err
	}

	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, execution_id::text, step_id, status, output, COALESCE(confirmed_by,''), confirmed_at
		FROM runbook_execution_steps
		WHERE execution_id=$1
		ORDER BY id ASC
	`, executionID)
	if err != nil {
		return RunbookExecution{}, err
	}
	defer rows.Close()
	steps := make([]RunbookExecutionStep, 0)
	for rows.Next() {
		var st RunbookExecutionStep
		if err := rows.Scan(&st.ID, &st.ExecutionID, &st.StepID, &st.Status, &st.Output, &st.ConfirmedBy, &st.ConfirmedAt); err != nil {
			return RunbookExecution{}, err
		}
		steps = append(steps, st)
	}
	e.Steps = steps
	return e, rows.Err()
}
