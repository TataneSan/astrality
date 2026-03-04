package httpapi

import "testing"

func TestMakeNodeFactMapsAgentVersion(t *testing.T) {
	req := factsReq{
		Kernel:      "6.8",
		CPUModel:    "x",
		CPUCores:    8,
		MemTotalMB:  16000,
		DiskTotalGB: 500,
		AgentVer:    "1.2.3",
	}
	fact := makeNodeFact("node-1", req)
	if fact.AgentVersion != "1.2.3" {
		t.Fatalf("expected agent version to be mapped, got %q", fact.AgentVersion)
	}
}

func TestNormalizeCommands(t *testing.T) {
	got := normalizeCommands([]string{" uname ", "uptime", "uname", "", " df "})
	if len(got) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(got))
	}
}

func TestIsCommandAllowed(t *testing.T) {
	if !isCommandAllowed("uname", []string{"uname", "uptime"}) {
		t.Fatalf("expected command allowed")
	}
	if isCommandAllowed("rm", []string{"uname", "uptime"}) {
		t.Fatalf("expected command denied")
	}
}
