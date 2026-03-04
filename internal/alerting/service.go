package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"astrality/internal/config"
	"astrality/internal/db"
)

type Service struct {
	cfg    config.Config
	store  *db.Store
	client *http.Client
}

func New(cfg config.Config, store *db.Store) *Service {
	return &Service{
		cfg:   cfg,
		store: store,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *Service) Start(ctx context.Context) {
	evalTick := time.NewTicker(time.Duration(maxInt(s.cfg.AlertEvalSec, 5)) * time.Second)
	notifyTick := time.NewTicker(time.Duration(maxInt(s.cfg.NotifyScanSec, 2)) * time.Second)

	go func() {
		defer evalTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-evalTick.C:
				s.runEval(ctx)
			}
		}
	}()

	go func() {
		defer notifyTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-notifyTick.C:
				s.runNotify(ctx)
			}
		}
	}()
}

func (s *Service) runEval(ctx context.Context) {
	rules, err := s.store.ListEnabledAlertRules(ctx)
	if err != nil {
		log.Printf("alert eval: list rules error: %v", err)
		return
	}
	offlineRatio, p95, err := s.store.ComputeHeartbeatStats(ctx, time.Duration(s.cfg.HeartbeatOfflineSec)*time.Second)
	if err != nil {
		log.Printf("alert eval: compute heartbeat stats error: %v", err)
		return
	}

	now := time.Now().UTC()
	_ = s.store.InsertSLOSnapshot(ctx, db.SLOSnapshot{
		WindowStart:              now.Add(-time.Duration(maxInt(s.cfg.AlertEvalSec, 5)) * time.Second),
		WindowEnd:                now,
		ControlPlaneAvailability: 1.0,
		HeartbeatFreshnessP95Sec: p95,
		OfflineRatio:             offlineRatio,
	})

	for _, rule := range rules {
		triggered, message, fingerprint := evaluateRule(rule, offlineRatio, p95)
		if triggered {
			evt, isNew, err := s.store.OpenOrRefreshAlertEvent(ctx, rule, "cluster", "all", message, fingerprint)
			if err != nil {
				log.Printf("alert eval: open event error: %v", err)
			}
			if isNew {
				_ = s.store.InsertTimelineEvent(ctx, "alert_open", "", rule.Severity, "system", message, map[string]any{"event_id": evt.ID, "rule_id": rule.ID})
			}
			continue
		}
		if err := s.store.ResolveAlertEvent(ctx, rule.ID, fingerprint); err != nil {
			log.Printf("alert eval: resolve event error: %v", err)
		} else {
			_ = s.store.InsertTimelineEvent(ctx, "alert_resolved", "", rule.Severity, "system", "alert resolved", map[string]any{"rule_id": rule.ID, "fingerprint": fingerprint})
		}
	}
}

func evaluateRule(rule db.AlertRule, offlineRatio, p95 float64) (bool, string, string) {
	switch rule.QueryType {
	case "offline_ratio_gt":
		threshold := floatFromMap(rule.QueryConfig, "threshold", 0.2)
		ok := offlineRatio > threshold
		msg := fmt.Sprintf("offline_ratio=%.4f threshold=%.4f", offlineRatio, threshold)
		return ok, msg, "offline_ratio_gt:cluster"
	case "heartbeat_freshness_p95_gt":
		threshold := floatFromMap(rule.QueryConfig, "threshold", 90)
		ok := p95 > threshold
		msg := fmt.Sprintf("heartbeat_freshness_p95_sec=%.2f threshold=%.2f", p95, threshold)
		return ok, msg, "heartbeat_freshness_p95_gt:cluster"
	default:
		return false, "", rule.QueryType + ":cluster"
	}
}

func (s *Service) runNotify(ctx context.Context) {
	pending, err := s.store.ListPendingNotifications(ctx, 100)
	if err != nil {
		log.Printf("notify: list pending error: %v", err)
		return
	}
	for _, p := range pending {
		err := s.sendNotification(ctx, p)
		if err != nil {
			_ = s.store.MarkNotificationFailed(ctx, p.AttemptID, err.Error(), 30*time.Second)
			_ = s.store.SetNotificationEndpointStatus(ctx, p.EndpointID, "error")
			continue
		}
		_ = s.store.MarkNotificationSent(ctx, p.AttemptID)
		_ = s.store.SetNotificationEndpointStatus(ctx, p.EndpointID, "ok")
	}
}

func (s *Service) sendNotification(ctx context.Context, p db.PendingNotification) error {
	switch p.EndpointType {
	case "webhook":
		return s.sendWebhook(ctx, p)
	case "email":
		return s.sendEmail(p)
	default:
		return fmt.Errorf("unsupported endpoint type: %s", p.EndpointType)
	}
}

func (s *Service) sendWebhook(ctx context.Context, p db.PendingNotification) error {
	url, _ := p.EndpointConfig["url"].(string)
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("missing webhook url")
	}
	payload := map[string]any{
		"event_id":    p.EventID,
		"severity":    p.EventSeverity,
		"message":     p.EventMessage,
		"fingerprint": p.EventFingerprint,
		"time":        time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.WebhookHMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.WebhookHMACSecret))
		_, _ = mac.Write(b)
		req.Header.Set("X-Astrality-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status=%d", resp.StatusCode)
	}
	return nil
}

func (s *Service) sendEmail(p db.PendingNotification) error {
	if s.cfg.SMTPHost == "" {
		return fmt.Errorf("smtp not configured")
	}
	toList := extractEmails(p.EndpointConfig["to"])
	if len(toList) == 0 {
		return fmt.Errorf("missing email recipients")
	}
	subjectPrefix, _ := p.EndpointConfig["subject_prefix"].(string)
	if subjectPrefix == "" {
		subjectPrefix = "[astrality]"
	}
	subject := fmt.Sprintf("%s %s", subjectPrefix, strings.ToUpper(p.EventSeverity))
	body := fmt.Sprintf("Event: %s\nSeverity: %s\nMessage: %s\n", p.EventID, p.EventSeverity, p.EventMessage)
	msg := []byte("To: " + strings.Join(toList, ",") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body)

	addr := s.cfg.SMTPHost + ":" + strconv.Itoa(s.cfg.SMTPPort)
	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	}
	return smtp.SendMail(addr, auth, s.cfg.SMTPFrom, toList, msg)
}

func extractEmails(v any) []string {
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			e := strings.TrimSpace(p)
			if e != "" {
				out = append(out, e)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func floatFromMap(m map[string]any, key string, d float64) float64 {
	v, ok := m[key]
	if !ok {
		return d
	}
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err == nil {
			return f
		}
	}
	return d
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
