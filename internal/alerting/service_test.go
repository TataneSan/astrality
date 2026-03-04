package alerting

import (
	"testing"

	"astrality/internal/db"
)

func TestEvaluateRuleOfflineRatio(t *testing.T) {
	rule := db.AlertRule{QueryType: "offline_ratio_gt", QueryConfig: map[string]any{"threshold": 0.2}}
	ok, _, _ := evaluateRule(rule, 0.3, 10)
	if !ok {
		t.Fatalf("expected trigger")
	}
	ok, _, _ = evaluateRule(rule, 0.1, 10)
	if ok {
		t.Fatalf("expected no trigger")
	}
}

func TestEvaluateRuleFreshness(t *testing.T) {
	rule := db.AlertRule{QueryType: "heartbeat_freshness_p95_gt", QueryConfig: map[string]any{"threshold": 30.0}}
	ok, _, _ := evaluateRule(rule, 0.0, 45)
	if !ok {
		t.Fatalf("expected trigger")
	}
}

func TestExtractEmails(t *testing.T) {
	emails := extractEmails("a@example.com,b@example.com")
	if len(emails) != 2 {
		t.Fatalf("expected 2 emails")
	}
}
