package db

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AlertRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	QueryType   string         `json:"query_type"`
	QueryConfig map[string]any `json:"query_config"`
	Severity    string         `json:"severity"`
	Enabled     bool           `json:"enabled"`
	CooldownSec int            `json:"cooldown_sec"`
	ChannelIDs  []string       `json:"channel_ids"`
	MuteUntil   *time.Time     `json:"mute_until,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type AlertEvent struct {
	ID             string     `json:"id"`
	RuleID         string     `json:"rule_id"`
	TargetType     string     `json:"target_type"`
	TargetID       string     `json:"target_id"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Message        string     `json:"message"`
	Fingerprint    string     `json:"fingerprint"`
	LastNotifiedAt *time.Time `json:"last_notified_at,omitempty"`
	OpenedAt       time.Time  `json:"opened_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type NotificationEndpoint struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Config     map[string]any `json:"config"`
	Enabled    bool           `json:"enabled"`
	LastStatus string         `json:"last_status"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type PendingNotification struct {
	AttemptID        string         `json:"attempt_id"`
	EventID          string         `json:"event_id"`
	EndpointID       string         `json:"endpoint_id"`
	EndpointType     string         `json:"endpoint_type"`
	EndpointConfig   map[string]any `json:"endpoint_config"`
	EventSeverity    string         `json:"event_severity"`
	EventMessage     string         `json:"event_message"`
	EventFingerprint string         `json:"event_fingerprint"`
}

type SLOSnapshot struct {
	WindowStart              time.Time `json:"window_start"`
	WindowEnd                time.Time `json:"window_end"`
	ControlPlaneAvailability float64   `json:"control_plane_availability"`
	HeartbeatFreshnessP95Sec float64   `json:"heartbeat_freshness_p95_sec"`
	OfflineRatio             float64   `json:"offline_ratio"`
	CreatedAt                time.Time `json:"created_at"`
}

func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, name, query_type, query_config, severity, enabled, cooldown_sec, channel_ids::text[], mute_until, created_at, updated_at
		FROM alert_rules
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertRule, 0)
	for rows.Next() {
		var r AlertRule
		var cfg []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.QueryType, &cfg, &r.Severity, &r.Enabled, &r.CooldownSec, &r.ChannelIDs, &r.MuteUntil, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.QueryConfig = map[string]any{}
		_ = json.Unmarshal(cfg, &r.QueryConfig)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabledAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, name, query_type, query_config, severity, enabled, cooldown_sec, channel_ids::text[], mute_until, created_at, updated_at
		FROM alert_rules
		WHERE enabled=true
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertRule, 0)
	for rows.Next() {
		var r AlertRule
		var cfg []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.QueryType, &cfg, &r.Severity, &r.Enabled, &r.CooldownSec, &r.ChannelIDs, &r.MuteUntil, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.QueryConfig = map[string]any{}
		_ = json.Unmarshal(cfg, &r.QueryConfig)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	if r.CooldownSec <= 0 {
		r.CooldownSec = 300
	}
	cfg, _ := json.Marshal(r.QueryConfig)
	r.ID = uuid.NewString()
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO alert_rules(id, name, query_type, query_config, severity, enabled, cooldown_sec, channel_ids)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8::uuid[])
		RETURNING created_at, updated_at
	`, r.ID, r.Name, r.QueryType, cfg, r.Severity, r.Enabled, r.CooldownSec, r.ChannelIDs).Scan(&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return AlertRule{}, err
	}
	return r, nil
}

func (s *Store) UpdateAlertRule(ctx context.Context, id string, r AlertRule) error {
	cfg, _ := json.Marshal(r.QueryConfig)
	_, err := s.Pool.Exec(ctx, `
		UPDATE alert_rules
		SET name=$2,
			query_type=$3,
			query_config=$4,
			severity=$5,
			enabled=$6,
			cooldown_sec=$7,
			channel_ids=$8::uuid[],
			updated_at=now()
		WHERE id=$1
	`, id, r.Name, r.QueryType, cfg, r.Severity, r.Enabled, r.CooldownSec, r.ChannelIDs)
	return err
}

func (s *Store) MuteAlertRule(ctx context.Context, id string, until time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE alert_rules SET mute_until=$2, updated_at=now() WHERE id=$1`, id, until)
	return err
}

func (s *Store) UnmuteAlertRule(ctx context.Context, id string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE alert_rules SET mute_until=NULL, updated_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) ListAlertEvents(ctx context.Context, limit int, status, severity string) ([]AlertEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, rule_id::text, target_type, target_id, severity, status, message, fingerprint, last_notified_at, opened_at, resolved_at, updated_at
		FROM alert_events
		WHERE ($1='' OR status=$1)
		  AND ($2='' OR severity=$2)
		ORDER BY opened_at DESC
		LIMIT $3
	`, status, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertEvent, 0)
	for rows.Next() {
		var e AlertEvent
		if err := rows.Scan(&e.ID, &e.RuleID, &e.TargetType, &e.TargetID, &e.Severity, &e.Status, &e.Message, &e.Fingerprint, &e.LastNotifiedAt, &e.OpenedAt, &e.ResolvedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AckAlertEvent(ctx context.Context, id string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE alert_events SET status='ack', updated_at=now() WHERE id=$1 AND status='open'`, id)
	return err
}

func (s *Store) OpenOrRefreshAlertEvent(ctx context.Context, rule AlertRule, targetType, targetID, message, fingerprint string) (AlertEvent, bool, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AlertEvent{}, false, err
	}
	defer tx.Rollback(ctx)

	var existing AlertEvent
	err = tx.QueryRow(ctx, `
		SELECT id::text, rule_id::text, target_type, target_id, severity, status, message, fingerprint, last_notified_at, opened_at, resolved_at, updated_at
		FROM alert_events
		WHERE rule_id=$1 AND fingerprint=$2 AND status='open'
		FOR UPDATE
	`, rule.ID, fingerprint).Scan(&existing.ID, &existing.RuleID, &existing.TargetType, &existing.TargetID, &existing.Severity, &existing.Status, &existing.Message, &existing.Fingerprint, &existing.LastNotifiedAt, &existing.OpenedAt, &existing.ResolvedAt, &existing.UpdatedAt)

	isNew := false
	if err != nil {
		if err != pgx.ErrNoRows {
			return AlertEvent{}, false, err
		}
		e := AlertEvent{
			ID:          uuid.NewString(),
			RuleID:      rule.ID,
			TargetType:  targetType,
			TargetID:    targetID,
			Severity:    rule.Severity,
			Status:      "open",
			Message:     message,
			Fingerprint: fingerprint,
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO alert_events(id, rule_id, target_type, target_id, severity, status, message, fingerprint)
			VALUES($1,$2,$3,$4,$5,'open',$6,$7)
			RETURNING opened_at, updated_at
		`, e.ID, e.RuleID, e.TargetType, e.TargetID, e.Severity, e.Message, e.Fingerprint).Scan(&e.OpenedAt, &e.UpdatedAt)
		if err != nil {
			return AlertEvent{}, false, err
		}
		existing = e
		isNew = true
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE alert_events
			SET message=$2, severity=$3, updated_at=now()
			WHERE id=$1
		`, existing.ID, message, rule.Severity)
		if err != nil {
			return AlertEvent{}, false, err
		}
	}

	if !isRuleMuted(rule) && shouldNotify(existing.LastNotifiedAt, rule.CooldownSec) {
		for _, endpointID := range rule.ChannelIDs {
			if strings.TrimSpace(endpointID) == "" {
				continue
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO notification_attempts(id, event_id, endpoint_id, status, next_attempt_at)
				VALUES($1,$2,$3,'pending',now())
				ON CONFLICT(event_id, endpoint_id) DO UPDATE
				SET status='pending', next_attempt_at=now(), updated_at=now()
			`, uuid.NewString(), existing.ID, endpointID)
			if err != nil {
				return AlertEvent{}, false, err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE alert_events SET last_notified_at=now(), updated_at=now() WHERE id=$1`, existing.ID)
		if err != nil {
			return AlertEvent{}, false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return AlertEvent{}, false, err
	}
	return existing, isNew, nil
}

func (s *Store) ResolveAlertEvent(ctx context.Context, ruleID, fingerprint string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE alert_events
		SET status='resolved', resolved_at=now(), updated_at=now()
		WHERE rule_id=$1 AND fingerprint=$2 AND status IN ('open','ack')
	`, ruleID, fingerprint)
	return err
}

func (s *Store) ListNotificationEndpoints(ctx context.Context) ([]NotificationEndpoint, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id::text, name, type, config, enabled, last_status, created_at, updated_at
		FROM notification_endpoints
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]NotificationEndpoint, 0)
	for rows.Next() {
		var e NotificationEndpoint
		var cfg []byte
		if err := rows.Scan(&e.ID, &e.Name, &e.Type, &cfg, &e.Enabled, &e.LastStatus, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.Config = map[string]any{}
		_ = json.Unmarshal(cfg, &e.Config)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CreateNotificationEndpoint(ctx context.Context, ep NotificationEndpoint) (NotificationEndpoint, error) {
	ep.ID = uuid.NewString()
	cfg, _ := json.Marshal(ep.Config)
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO notification_endpoints(id, name, type, config, enabled)
		VALUES($1,$2,$3,$4,$5)
		RETURNING created_at, updated_at
	`, ep.ID, ep.Name, ep.Type, cfg, ep.Enabled).Scan(&ep.CreatedAt, &ep.UpdatedAt)
	if err != nil {
		return NotificationEndpoint{}, err
	}
	return ep, nil
}

func (s *Store) UpdateNotificationEndpoint(ctx context.Context, id string, ep NotificationEndpoint) error {
	cfg, _ := json.Marshal(ep.Config)
	_, err := s.Pool.Exec(ctx, `
		UPDATE notification_endpoints
		SET name=$2, type=$3, config=$4, enabled=$5, updated_at=now()
		WHERE id=$1
	`, id, ep.Name, ep.Type, cfg, ep.Enabled)
	return err
}

func (s *Store) ListPendingNotifications(ctx context.Context, limit int) ([]PendingNotification, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT na.id::text, na.event_id::text, na.endpoint_id::text,
		       ne.type, ne.config, ae.severity, ae.message, ae.fingerprint
		FROM notification_attempts na
		JOIN notification_endpoints ne ON ne.id=na.endpoint_id
		JOIN alert_events ae ON ae.id=na.event_id
		WHERE na.status IN ('pending','retrying')
		  AND na.next_attempt_at <= now()
		  AND ne.enabled=true
		ORDER BY na.next_attempt_at ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PendingNotification, 0)
	for rows.Next() {
		var n PendingNotification
		var cfg []byte
		if err := rows.Scan(&n.AttemptID, &n.EventID, &n.EndpointID, &n.EndpointType, &cfg, &n.EventSeverity, &n.EventMessage, &n.EventFingerprint); err != nil {
			return nil, err
		}
		n.EndpointConfig = map[string]any{}
		_ = json.Unmarshal(cfg, &n.EndpointConfig)
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) MarkNotificationSent(ctx context.Context, attemptID string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE notification_attempts
		SET status='sent', updated_at=now(), attempt_count=attempt_count+1
		WHERE id=$1
	`, attemptID)
	return err
}

func (s *Store) MarkNotificationFailed(ctx context.Context, attemptID, lastError string, backoff time.Duration) error {
	if backoff <= 0 {
		backoff = 15 * time.Second
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE notification_attempts
		SET status='retrying',
			attempt_count=attempt_count+1,
			last_error=$2,
			next_attempt_at=now()+$3::interval,
			updated_at=now()
		WHERE id=$1
	`, attemptID, truncateText(lastError, 1000), fmt.Sprintf("%f seconds", backoff.Seconds()))
	return err
}

func (s *Store) SetNotificationEndpointStatus(ctx context.Context, endpointID, status string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE notification_endpoints SET last_status=$2, updated_at=now() WHERE id=$1`, endpointID, truncateText(status, 200))
	return err
}

func (s *Store) InsertSLOSnapshot(ctx context.Context, snap SLOSnapshot) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO slo_snapshots(window_start, window_end, control_plane_availability, heartbeat_freshness_p95_sec, offline_ratio)
		VALUES($1,$2,$3,$4,$5)
	`, snap.WindowStart, snap.WindowEnd, snap.ControlPlaneAvailability, snap.HeartbeatFreshnessP95Sec, snap.OfflineRatio)
	return err
}

func (s *Store) ListSLOSnapshots(ctx context.Context, limit int) ([]SLOSnapshot, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT window_start, window_end, control_plane_availability, heartbeat_freshness_p95_sec, offline_ratio, created_at
		FROM slo_snapshots
		ORDER BY window_end DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SLOSnapshot, 0)
	for rows.Next() {
		var s SLOSnapshot
		if err := rows.Scan(&s.WindowStart, &s.WindowEnd, &s.ControlPlaneAvailability, &s.HeartbeatFreshnessP95Sec, &s.OfflineRatio, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) ComputeHeartbeatStats(ctx context.Context, offlineAfter time.Duration) (offlineRatio float64, freshnessP95Sec float64, err error) {
	rows, err := s.Pool.Query(ctx, `SELECT status, last_seen FROM nodes WHERE status <> 'revoked'`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	now := time.Now()
	total := 0
	offline := 0
	ages := make([]float64, 0)
	for rows.Next() {
		var baseStatus string
		var lastSeen time.Time
		if err := rows.Scan(&baseStatus, &lastSeen); err != nil {
			return 0, 0, err
		}
		status := computeStatus(baseStatus, lastSeen, now, offlineAfter)
		total++
		if status == "offline" {
			offline++
		}
		ages = append(ages, now.Sub(lastSeen).Seconds())
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if total == 0 {
		return 0, 0, nil
	}
	offlineRatio = float64(offline) / float64(total)
	sort.Float64s(ages)
	idx := int(0.95 * float64(len(ages)-1))
	if idx < 0 {
		idx = 0
	}
	freshnessP95Sec = ages[idx]
	return offlineRatio, freshnessP95Sec, nil
}

func isRuleMuted(rule AlertRule) bool {
	return rule.MuteUntil != nil && rule.MuteUntil.After(time.Now())
}

func shouldNotify(last *time.Time, cooldownSec int) bool {
	if cooldownSec <= 0 {
		cooldownSec = 300
	}
	if last == nil {
		return true
	}
	return time.Since(*last) >= time.Duration(cooldownSec)*time.Second
}

func truncateText(in string, max int) string {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max]
}
