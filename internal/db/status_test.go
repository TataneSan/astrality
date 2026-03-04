package db

import (
	"testing"
	"time"
)

func TestComputeStatus(t *testing.T) {
	now := time.Now()
	offlineAfter := 60 * time.Second

	if got := computeStatus("revoked", now, now, offlineAfter); got != "revoked" {
		t.Fatalf("expected revoked, got %s", got)
	}
	if got := computeStatus("online", now.Add(-20*time.Second), now, offlineAfter); got != "online" {
		t.Fatalf("expected online, got %s", got)
	}
	if got := computeStatus("online", now.Add(-40*time.Second), now, offlineAfter); got != "degraded" {
		t.Fatalf("expected degraded, got %s", got)
	}
	if got := computeStatus("online", now.Add(-70*time.Second), now, offlineAfter); got != "offline" {
		t.Fatalf("expected offline, got %s", got)
	}
}
