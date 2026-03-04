package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type agentConfig struct {
	ServerURL         string
	DataDir           string
	EnrollToken       string
	AgentVersion      string
	HeartbeatSec      int
	FactsSec          int
	InsecureEnrollTLS bool
	InsecureHTTP      bool
	EnvFile           string
	JobPollSec        int
	JobAllowlist      []string
}

type agentState struct {
	NodeID     string `json:"node_id"`
	AgentToken string `json:"agent_token"`
}

type enrollResp struct {
	NodeID        string `json:"node_id"`
	AgentToken    string `json:"agent_token"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	CAPEM         string `json:"ca_pem"`
	HeartbeatSec  int    `json:"heartbeat_interval_sec"`
}

type cpuSample struct {
	idle  uint64
	total uint64
	valid bool
}

type cpuSampler struct {
	mu sync.Mutex
	p  cpuSample
}

func main() {
	cfg := loadConfig()
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	state, err := loadState(cfg.DataDir)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	if state.NodeID == "" || state.AgentToken == "" || !certFilesPresent(cfg.DataDir) {
		if cfg.EnrollToken == "" {
			log.Fatalf("ENROLL_TOKEN required for first startup")
		}
		resp, err := enroll(cfg)
		if err != nil {
			log.Fatalf("enroll failed: %v", err)
		}
		state.NodeID = resp.NodeID
		state.AgentToken = resp.AgentToken
		if err := os.WriteFile(filepath.Join(cfg.DataDir, "agent.crt"), []byte(resp.ClientCertPEM), 0o640); err != nil {
			log.Fatalf("write agent cert: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cfg.DataDir, "agent.key"), []byte(resp.ClientKeyPEM), 0o600); err != nil {
			log.Fatalf("write agent key: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cfg.DataDir, "ca.pem"), []byte(resp.CAPEM), 0o640); err != nil {
			log.Fatalf("write ca cert: %v", err)
		}
		if resp.HeartbeatSec > 0 {
			cfg.HeartbeatSec = resp.HeartbeatSec
		}
		if err := saveState(cfg.DataDir, state); err != nil {
			log.Fatalf("save state: %v", err)
		}
		if err := clearEnrollToken(cfg.EnvFile); err != nil {
			log.Printf("warning: failed to clear ENROLL_TOKEN from env file: %v", err)
		}
	}

	client, err := buildAgentClient(cfg)
	if err != nil {
		log.Fatalf("client init: %v", err)
	}

	sampler := &cpuSampler{}
	sendLog(context.Background(), client, cfg, state, "info", "agent.started")
	sendFacts(context.Background(), client, cfg, state)
	sendHeartbeat(context.Background(), sampler, client, cfg, state)

	hbTick := time.NewTicker(time.Duration(cfg.HeartbeatSec) * time.Second)
	factsTick := time.NewTicker(time.Duration(cfg.FactsSec) * time.Second)
	jobTick := time.NewTicker(time.Duration(cfg.JobPollSec) * time.Second)
	defer hbTick.Stop()
	defer factsTick.Stop()
	defer jobTick.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-hbTick.C:
			sendHeartbeat(context.Background(), sampler, client, cfg, state)
		case <-factsTick.C:
			sendFacts(context.Background(), client, cfg, state)
		case <-jobTick.C:
			runOneJob(context.Background(), client, cfg, state)
		case <-ctx.Done():
			sendLog(context.Background(), client, cfg, state, "info", "agent.stopped")
			return
		}
	}
}

func loadConfig() agentConfig {
	return agentConfig{
		ServerURL:         getenv("SERVER_URL", "https://127.0.0.1:8443"),
		DataDir:           getenv("DATA_DIR", "/etc/astrality"),
		EnrollToken:       os.Getenv("ENROLL_TOKEN"),
		AgentVersion:      getenv("AGENT_VERSION", "0.1.0"),
		HeartbeatSec:      getenvInt("HEARTBEAT_SEC", 15),
		FactsSec:          getenvInt("FACTS_SEC", 300),
		InsecureEnrollTLS: getenvBool("INSECURE_ENROLL_TLS", false),
		InsecureHTTP:      getenvBool("INSECURE_HTTP", false),
		EnvFile:           getenv("AGENT_ENV_FILE", ""),
		JobPollSec:        getenvInt("JOB_POLL_SEC", 5),
		JobAllowlist:      parseAllowlist(getenv("JOB_ALLOWLIST", "uname,uptime,df,free,echo,cat,ls,systemctl,journalctl")),
	}
}

func clearEnrollToken(envFile string) error {
	if strings.TrimSpace(envFile) == "" {
		return nil
	}
	b, err := os.ReadFile(envFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "ENROLL_TOKEN=") {
			continue
		}
		out = append(out, ln)
	}
	tmp := envFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, envFile)
}

func certFilesPresent(dataDir string) bool {
	files := []string{"agent.crt", "agent.key", "ca.pem"}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dataDir, f)); err != nil {
			return false
		}
	}
	return true
}

func statePath(dataDir string) string {
	return filepath.Join(dataDir, "state.json")
}

func loadState(dataDir string) (agentState, error) {
	p := statePath(dataDir)
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return agentState{}, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return agentState{}, err
	}
	var s agentState
	if err := json.Unmarshal(b, &s); err != nil {
		return agentState{}, err
	}
	return s, nil
}

func saveState(dataDir string, s agentState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(dataDir), b, 0o600)
}

func enroll(cfg agentConfig) (enrollResp, error) {
	hostname, _ := os.Hostname()
	payload := map[string]any{
		"token":         cfg.EnrollToken,
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"ip":            localIP(),
		"agent_version": cfg.AgentVersion,
	}
	b, _ := json.Marshal(payload)
	tr := &http.Transport{}
	if strings.HasPrefix(cfg.ServerURL, "https://") {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureEnrollTLS}
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	resp, err := client.Post(strings.TrimRight(cfg.ServerURL, "/")+"/api/v1/enroll", "application/json", bytes.NewReader(b))
	if err != nil {
		return enrollResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return enrollResp{}, fmt.Errorf("enroll status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out enrollResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return enrollResp{}, err
	}
	if out.NodeID == "" || out.AgentToken == "" {
		return enrollResp{}, errors.New("invalid enroll response")
	}
	return out, nil
}

func buildAgentClient(cfg agentConfig) (*http.Client, error) {
	if cfg.InsecureHTTP {
		return &http.Client{Timeout: 15 * time.Second}, nil
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(cfg.DataDir, "agent.crt"), filepath.Join(cfg.DataDir, "agent.key"))
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(filepath.Join(cfg.DataDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid ca pem")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}, nil
}

func sendHeartbeat(ctx context.Context, sampler *cpuSampler, client *http.Client, cfg agentConfig, st agentState) {
	cpu, mem, disk, load1, up := collectRuntimeStats(sampler)
	payload := map[string]any{
		"cpu_usage":  cpu,
		"mem_usage":  mem,
		"disk_usage": disk,
		"load1":      load1,
		"uptime_sec": up,
		"ts":         time.Now().UTC().Format(time.RFC3339),
	}
	if err := postJSON(ctx, client, cfg, st, "/api/v1/heartbeat", payload); err != nil {
		log.Printf("heartbeat error: %v", err)
	}
}

func sendFacts(ctx context.Context, client *http.Client, cfg agentConfig, st agentState) {
	payload := map[string]any{
		"kernel":        kernelRelease(),
		"cpu_model":     cpuModel(),
		"cpu_cores":     runtime.NumCPU(),
		"mem_total_mb":  memTotalMB(),
		"disk_total_gb": diskTotalGB(),
		"agent_version": cfg.AgentVersion,
	}
	if err := postJSON(ctx, client, cfg, st, "/api/v1/facts", payload); err != nil {
		log.Printf("facts error: %v", err)
	}
}

func sendLog(ctx context.Context, client *http.Client, cfg agentConfig, st agentState, level, message string) {
	payload := map[string]any{"level": level, "message": message, "ts": time.Now().UTC().Format(time.RFC3339)}
	if err := postJSON(ctx, client, cfg, st, "/api/v1/logs", payload); err != nil {
		log.Printf("log shipping error: %v", err)
	}
}

type jobTask struct {
	RunID      string   `json:"run_id"`
	JobID      string   `json:"job_id"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	TimeoutSec int      `json:"timeout_sec"`
	Attempt    int      `json:"attempt"`
	MaxRetries int      `json:"max_retries"`
}

type jobResult struct {
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

func runOneJob(ctx context.Context, client *http.Client, cfg agentConfig, st agentState) {
	task, err := pollNextJob(ctx, client, cfg, st)
	if err != nil {
		log.Printf("job poll error: %v", err)
		return
	}
	if task == nil {
		return
	}

	res := executeJob(cfg, *task)
	if err := postJSON(ctx, client, cfg, st, "/api/v2/agent/jobs/"+task.RunID+"/result", res); err != nil {
		log.Printf("job result error: %v", err)
	}
}

func pollNextJob(ctx context.Context, client *http.Client, cfg agentConfig, st agentState) (*jobTask, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ServerURL, "/")+"/api/v2/agent/jobs/next", strings.NewReader(`{}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", st.AgentToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var task jobTask
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		return nil, err
	}
	return &task, nil
}

func executeJob(cfg agentConfig, task jobTask) jobResult {
	start := time.Now().UTC()
	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	if !isCommandAllowed(task.Command, cfg.JobAllowlist) {
		end := time.Now().UTC()
		return jobResult{
			Status:     "failed",
			ExitCode:   126,
			Stdout:     "",
			Stderr:     "command not allowed by local allowlist",
			StartedAt:  start.Format(time.RFC3339),
			FinishedAt: end.Format(time.RFC3339),
		}
	}

	execCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, task.Command, task.Args...)
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	exitCode := 0
	status := "succeeded"
	if err := cmd.Run(); err != nil {
		status = "failed"
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			status = "timed_out"
			exitCode = 124
		} else {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
	}

	stdout := outBuf.String()
	stderr := errBuf.String()
	if len(stdout) > 100000 {
		stdout = stdout[:100000]
	}
	if len(stderr) > 100000 {
		stderr = stderr[:100000]
	}
	end := time.Now().UTC()
	return jobResult{
		Status:     status,
		ExitCode:   exitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		StartedAt:  start.Format(time.RFC3339),
		FinishedAt: end.Format(time.RFC3339),
	}
}

func parseAllowlist(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func isCommandAllowed(command string, allowlist []string) bool {
	for _, v := range allowlist {
		if command == v {
			return true
		}
	}
	return false
}

func postJSON(ctx context.Context, client *http.Client, cfg agentConfig, st agentState, endpoint string, payload any) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ServerURL, "/")+endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", st.AgentToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func collectRuntimeStats(s *cpuSampler) (cpu, mem, disk, load1 float64, uptime int64) {
	cpu = s.usage()
	mem = memUsagePercent()
	disk = diskUsagePercent("/")
	load1 = loadAvg1()
	uptime = uptimeSec()
	return
}

func (s *cpuSampler) usage() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	idle, total, err := readCPUStat()
	if err != nil {
		return 0
	}
	if !s.p.valid {
		s.p = cpuSample{idle: idle, total: total, valid: true}
		return 0
	}
	idleDelta := float64(idle - s.p.idle)
	totalDelta := float64(total - s.p.total)
	s.p = cpuSample{idle: idle, total: total, valid: true}
	if totalDelta <= 0 {
		return 0
	}
	busy := (1 - (idleDelta / totalDelta)) * 100
	return math.Max(0, math.Min(100, busy))
}

func readCPUStat() (idle uint64, total uint64, err error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 {
		return 0, 0, errors.New("empty /proc/stat")
	}
	f := strings.Fields(lines[0])
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, errors.New("invalid cpu line")
	}
	vals := make([]uint64, 0, len(f)-1)
	for _, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		vals = append(vals, n)
		total += n
	}
	if len(vals) > 3 {
		idle = vals[3]
	}
	if len(vals) > 4 {
		idle += vals[4]
	}
	return idle, total, nil
}

func memUsagePercent() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var total, available float64
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "MemTotal:") {
			total = parseKBLine(ln)
		}
		if strings.HasPrefix(ln, "MemAvailable:") {
			available = parseKBLine(ln)
		}
	}
	if total <= 0 {
		return 0
	}
	used := ((total - available) / total) * 100
	return math.Max(0, math.Min(100, used))
}

func memTotalMB() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "MemTotal:") {
			kb := parseKBLine(ln)
			return int64(kb / 1024)
		}
	}
	return 0
}

func parseKBLine(s string) float64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.ParseFloat(fields[1], 64)
	return n
}

func diskUsagePercent(mount string) float64 {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(mount, &fs); err != nil {
		return 0
	}
	total := float64(fs.Blocks) * float64(fs.Bsize)
	avail := float64(fs.Bavail) * float64(fs.Bsize)
	if total == 0 {
		return 0
	}
	used := ((total - avail) / total) * 100
	return math.Max(0, math.Min(100, used))
}

func diskTotalGB() int64 {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		return 0
	}
	total := float64(fs.Blocks) * float64(fs.Bsize)
	return int64(total / (1024 * 1024 * 1024))
}

func loadAvg1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(f[0], 64)
	return n
}

func uptimeSec() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(f[0], 64)
	return int64(n)
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.ToLower(ln), "model name") {
			parts := strings.SplitN(ln, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}

func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "127.0.0.1"
	}
	return addr.IP.String()
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func getenvInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

func getenvBool(k string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return d
	}
	return v == "1" || v == "true" || v == "yes"
}
