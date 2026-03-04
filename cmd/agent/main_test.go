package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClearEnrollToken(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	content := "SERVER_URL=https://x\nENROLL_TOKEN=abc\nDATA_DIR=/etc/astrality\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clearEnrollToken(envPath); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ENROLL_TOKEN=") {
		t.Fatalf("expected ENROLL_TOKEN to be removed")
	}
}

func TestParseAllowlist(t *testing.T) {
	got := parseAllowlist("uname, uptime,uname,,df")
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
}

func TestIsCommandAllowed(t *testing.T) {
	if !isCommandAllowed("uname", []string{"uname", "uptime"}) {
		t.Fatalf("expected allowed command")
	}
	if isCommandAllowed("rm", []string{"uname", "uptime"}) {
		t.Fatalf("expected denied command")
	}
}
