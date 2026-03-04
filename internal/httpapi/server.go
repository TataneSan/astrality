package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"astrality/internal/auth"
	"astrality/internal/config"
	"astrality/internal/console"
	"astrality/internal/db"
	"astrality/internal/enroll"
	"astrality/internal/logs"
	"astrality/internal/metrics"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	cfg      config.Config
	store    *db.Store
	auth     *auth.Authenticator
	ca       *enroll.CA
	m        *metrics.Registry
	enrollRL *enrollRateLimiter
}

func New(cfg config.Config, store *db.Store, a *auth.Authenticator, ca *enroll.CA, m *metrics.Registry) *Server {
	return &Server{
		cfg:      cfg,
		store:    store,
		auth:     a,
		ca:       ca,
		m:        m,
		enrollRL: newEnrollRateLimiter(cfg.EnrollRatePerMinute),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/api/v1/enrollment-tokens", s.withUserRole("admin", s.handleEnrollmentToken))
	mux.HandleFunc("/api/v1/enroll", s.handleEnroll)
	mux.HandleFunc("/api/v1/agents/rotate", s.handleAgentRotate)
	mux.HandleFunc("/api/v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/v1/facts", s.handleFacts)
	mux.HandleFunc("/api/v1/logs", s.handleAgentLogs)
	mux.HandleFunc("/api/v1/nodes", s.withUserRole("viewer", s.handleNodes))
	mux.HandleFunc("/api/v1/nodes/", s.withUserRole("viewer", s.handleNodeSubroutes))
	mux.HandleFunc("/api/v2/jobs", s.withUserRole("viewer", s.handleV2Jobs))
	mux.HandleFunc("/api/v2/jobs/", s.withUserRole("viewer", s.handleV2JobSubroutes))
	mux.HandleFunc("/api/v2/policies/allowlist", s.withUserRole("viewer", s.handleV2Allowlist))
	mux.HandleFunc("/api/v2/alerts/rules", s.withUserRole("viewer", s.handleV2AlertRules))
	mux.HandleFunc("/api/v2/alerts/rules/", s.withUserRole("viewer", s.handleV2AlertRuleSubroutes))
	mux.HandleFunc("/api/v2/alerts/events", s.withUserRole("viewer", s.handleV2AlertEvents))
	mux.HandleFunc("/api/v2/alerts/events/", s.withUserRole("viewer", s.handleV2AlertEventSubroutes))
	mux.HandleFunc("/api/v2/notifications/endpoints", s.withUserRole("viewer", s.handleV2NotificationEndpoints))
	mux.HandleFunc("/api/v2/notifications/endpoints/", s.withUserRole("viewer", s.handleV2NotificationEndpointSubroutes))
	mux.HandleFunc("/api/v2/slo/snapshots", s.withUserRole("viewer", s.handleV2SLOSnapshots))
	mux.HandleFunc("/api/v2/agent/jobs/next", s.handleV2AgentNextJob)
	mux.HandleFunc("/api/v2/agent/jobs/", s.handleV2AgentJobSubroutes)

	if _, err := os.Stat("./web"); err == nil {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./web"))))
	}
	if _, err := os.Stat("./artifacts"); err == nil {
		mux.Handle("/artifacts/", http.StripPrefix("/artifacts/", http.FileServer(http.Dir("./artifacts"))))
	}
	mux.HandleFunc("/", s.handleIndex)

	return s.instrument(mux)
}

func (s *Server) TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.MinVersion = tls.VersionTLS12
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	return cfg
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	f := "./web/index.html"
	if _, err := os.Stat(f); err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("astrality control-plane"))
		return
	}
	http.ServeFile(w, r, f)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC()})
}

type createTokenReq struct {
	TTLMinutes int `json:"ttl_minutes"`
}

func (s *Server) handleEnrollmentToken(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req createTokenReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.TTLMinutes <= 0 || req.TTLMinutes > 1440 {
		req.TTLMinutes = 30
	}
	token := randomToken(40)
	if err := s.store.CreateEnrollmentToken(r.Context(), db.HashToken(token), time.Now().Add(time.Duration(req.TTLMinutes)*time.Minute), p.Subject); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.InsertAudit(r.Context(), p.Subject, "enrollment_token.created", "", map[string]any{"ttl_minutes": req.TTLMinutes})
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expires_in_minutes": req.TTLMinutes})
}

type enrollReq struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	IP           string `json:"ip"`
	AgentVersion string `json:"agent_version"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.enrollRL.Allow(remoteIP(r.RemoteAddr)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	var req enrollReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Token == "" || req.Hostname == "" {
		writeErr(w, http.StatusBadRequest, "token and hostname are required")
		return
	}
	if req.IP == "" {
		req.IP = remoteIP(r.RemoteAddr)
	}
	if req.OS == "" {
		req.OS = "linux"
	}
	if req.Arch == "" {
		req.Arch = "unknown"
	}
	if req.AgentVersion == "" {
		req.AgentVersion = "unknown"
	}

	if err := s.store.ConsumeEnrollmentToken(r.Context(), db.HashToken(req.Token)); err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := uuid.NewString()
	agentToken := randomToken(48)
	if err := s.store.RegisterNode(r.Context(), id, req.Hostname, req.OS, req.Arch, req.IP, req.AgentVersion, db.HashToken(agentToken)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	certPEM, keyPEM, err := s.ca.IssueNodeCert(id, s.cfg.NodeCertTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.InsertAudit(r.Context(), "system", "node.enrolled", id, map[string]any{"hostname": req.Hostname, "ip": req.IP})
	writeJSON(w, http.StatusCreated, map[string]any{
		"node_id":                id,
		"agent_token":            agentToken,
		"client_cert_pem":        string(certPEM),
		"client_key_pem":         string(keyPEM),
		"ca_pem":                 string(s.ca.CertPEM),
		"heartbeat_interval_sec": 15,
	})
}

func (s *Server) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID, err := s.authenticateAgent(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	oldToken := strings.TrimSpace(r.Header.Get("X-Agent-Token"))
	newToken := randomToken(48)
	certPEM, keyPEM, err := s.ca.IssueNodeCert(nodeID, s.cfg.NodeCertTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.RotateNodeAuthToken(r.Context(), nodeID, db.HashToken(oldToken), db.HashToken(newToken)); err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	_ = s.store.InsertAudit(r.Context(), "agent:"+nodeID, "agent.rotate", nodeID, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":         nodeID,
		"agent_token":     newToken,
		"client_cert_pem": string(certPEM),
		"client_key_pem":  string(keyPEM),
		"ca_pem":          string(s.ca.CertPEM),
	})
}

type heartbeatReq struct {
	CPUUsage  float64 `json:"cpu_usage"`
	MemUsage  float64 `json:"mem_usage"`
	DiskUsage float64 `json:"disk_usage"`
	Load1     float64 `json:"load1"`
	UptimeSec int64   `json:"uptime_sec"`
	TS        string  `json:"ts"`
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID, err := s.authenticateAgent(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req heartbeatReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ts := time.Now().UTC()
	if strings.TrimSpace(req.TS) != "" {
		if parsed, err := time.Parse(time.RFC3339, req.TS); err == nil {
			ts = parsed
		}
	}
	err = s.store.InsertHeartbeat(r.Context(), db.Heartbeat{
		NodeID: nodeID, CPUUsage: req.CPUUsage, MemUsage: req.MemUsage, DiskUsage: req.DiskUsage,
		Load1: req.Load1, UptimeSec: req.UptimeSec, TS: ts,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.m.HeartbeatsTotal.WithLabelValues("ok").Inc()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type factsReq struct {
	Kernel      string `json:"kernel"`
	CPUModel    string `json:"cpu_model"`
	CPUCores    int    `json:"cpu_cores"`
	MemTotalMB  int64  `json:"mem_total_mb"`
	DiskTotalGB int64  `json:"disk_total_gb"`
	AgentVer    string `json:"agent_version"`
}

func (s *Server) handleFacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID, err := s.authenticateAgent(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req factsReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.store.UpsertFacts(r.Context(), makeNodeFact(nodeID, req))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func makeNodeFact(nodeID string, req factsReq) db.NodeFact {
	return db.NodeFact{
		NodeID:       nodeID,
		Kernel:       req.Kernel,
		CPUModel:     req.CPUModel,
		CPUCores:     req.CPUCores,
		MemTotalMB:   req.MemTotalMB,
		DiskTotalGB:  req.DiskTotalGB,
		AgentVersion: req.AgentVer,
		UpdatedAt:    time.Now().UTC(),
	}
}

type agentLogReq struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	TS      string `json:"ts"`
}

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID, err := s.authenticateAgent(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req agentLogReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Level == "" {
		req.Level = logs.LevelInfo
	}
	ts := time.Now().UTC()
	if req.TS != "" {
		if t, err := time.Parse(time.RFC3339, req.TS); err == nil {
			ts = t
		}
	}
	if len(req.Message) > 2000 {
		req.Message = req.Message[:2000]
	}
	if err := s.store.InsertLog(r.Context(), db.LogEntry{NodeID: nodeID, Level: req.Level, Message: req.Message, TS: ts}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodes, err := s.store.ListNodes(r.Context(), time.Duration(s.cfg.HeartbeatOfflineSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.m.NodeCount.Set(float64(len(nodes)))
	writeJSON(w, http.StatusOK, map[string]any{"items": nodes})
}

func (s *Server) handleNodeSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	nodeID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		n, f, err := s.store.GetNode(r.Context(), nodeID, time.Duration(s.cfg.HeartbeatOfflineSec)*time.Second)
		if err != nil {
			writeErr(w, http.StatusNotFound, "node not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node": n, "facts": f})
		return
	}

	switch parts[1] {
	case "heartbeats":
		s.handleNodeHeartbeats(w, r, nodeID)
	case "logs":
		s.handleNodeLogs(w, r, nodeID)
	case "console":
		if len(parts) == 3 && parts[2] == "session" {
			s.handleConsoleSession(w, r, p, nodeID)
			return
		}
		writeErr(w, http.StatusNotFound, "not found")
	case "revoke":
		s.handleNodeRevoke(w, r, p, nodeID)
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleNodeHeartbeats(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListHeartbeats(r.Context(), nodeID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleNodeLogs(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListLogs(r.Context(), nodeID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleConsoleSession(w http.ResponseWriter, r *http.Request, p auth.Principal, nodeID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !auth.HasRole(p.Role, "operator") {
		writeErr(w, http.StatusForbidden, "insufficient role")
		return
	}
	n, _, err := s.store.GetNode(r.Context(), nodeID, time.Duration(s.cfg.HeartbeatOfflineSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	sessionID := uuid.NewString()
	cmd := console.BuildSSHCommand(s.cfg.BastionHost, n.IP)
	expires := time.Now().Add(s.cfg.SessionTTL)

	if err := s.store.InsertSSHSession(r.Context(), sessionID, nodeID, p.Subject, cmd, expires); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.InsertAudit(r.Context(), p.Subject, "console.session.created", nodeID, map[string]any{"session_id": sessionID})
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id":  sessionID,
		"ssh_command": cmd,
		"expires_at":  expires.UTC(),
	})
}

func (s *Server) handleNodeRevoke(w http.ResponseWriter, r *http.Request, p auth.Principal, nodeID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !auth.HasRole(p.Role, "admin") {
		writeErr(w, http.StatusForbidden, "insufficient role")
		return
	}
	if err := s.store.RevokeNode(r.Context(), nodeID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = s.store.InsertAudit(r.Context(), p.Subject, "node.revoked", nodeID, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) authenticateAgent(r *http.Request) (string, error) {
	token := strings.TrimSpace(r.Header.Get("X-Agent-Token"))
	if token == "" {
		return "", errors.New("missing X-Agent-Token")
	}
	nodeID, err := s.store.ResolveNodeByAuthToken(r.Context(), token)
	if err != nil {
		return "", errors.New("unauthorized")
	}
	if !s.cfg.InsecureHTTP {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return "", errors.New("mTLS client certificate required")
		}
		cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName)
		if cn == "" || cn != nodeID {
			return "", errors.New("client cert does not match node identity")
		}
	}
	return nodeID, nil
}

func (s *Server) withUserRole(role string, next func(http.ResponseWriter, *http.Request, auth.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.auth.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !auth.HasRole(principal.Role, role) {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		next(w, r, principal)
	}
}

func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeout := time.Duration(s.cfg.DBTimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)

		rw := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/v1/nodes/") {
			p = path.Join("/api/v1/nodes", "{id}")
		}
		if strings.HasPrefix(p, "/api/v2/jobs/") {
			p = path.Join("/api/v2/jobs", "{id}")
		}
		if strings.HasPrefix(p, "/api/v2/alerts/rules/") {
			p = path.Join("/api/v2/alerts/rules", "{id}")
		}
		if strings.HasPrefix(p, "/api/v2/alerts/events/") {
			p = path.Join("/api/v2/alerts/events", "{id}")
		}
		if strings.HasPrefix(p, "/api/v2/notifications/endpoints/") {
			p = path.Join("/api/v2/notifications/endpoints", "{id}")
		}
		if strings.HasPrefix(p, "/api/v2/agent/jobs/") {
			p = path.Join("/api/v2/agent/jobs", "{run_id}")
		}
		s.m.RequestsTotal.WithLabelValues(p, strconv.Itoa(rw.statusCode)).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func decodeJSON(body io.ReadCloser, dst any) error {
	defer body.Close()
	dec := json.NewDecoder(io.LimitReader(body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("invalid trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func randomToken(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return uuid.NewString()
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > n {
		return encoded[:n]
	}
	return encoded
}

type enrollRateLimiter struct {
	mu          sync.Mutex
	limitPerMin int
	entries     map[string]*enrollBucket
}

type enrollBucket struct {
	windowStart time.Time
	count       int
}

func newEnrollRateLimiter(limit int) *enrollRateLimiter {
	if limit <= 0 {
		limit = 30
	}
	return &enrollRateLimiter{
		limitPerMin: limit,
		entries:     make(map[string]*enrollBucket),
	}
}

func (r *enrollRateLimiter) Allow(key string) bool {
	now := time.Now()
	window := now.Truncate(time.Minute)

	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.entries[key]
	if !ok || !b.windowStart.Equal(window) {
		r.entries[key] = &enrollBucket{windowStart: window, count: 1}
		r.gc(now)
		return true
	}
	if b.count >= r.limitPerMin {
		return false
	}
	b.count++
	return true
}

func (r *enrollRateLimiter) gc(now time.Time) {
	threshold := now.Add(-2 * time.Minute)
	for k, v := range r.entries {
		if v.windowStart.Before(threshold) {
			delete(r.entries, k)
		}
	}
}

func Run(ctx context.Context, cfg config.Config, srv *Server, certFile, keyFile string) error {
	var tlsCfg *tls.Config
	if !cfg.InsecureHTTP {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(srv.ca.CertPEM); !ok {
			return fmt.Errorf("failed to append internal ca")
		}
		if cfg.ClientCAFile != "" {
			b, err := os.ReadFile(cfg.ClientCAFile)
			if err != nil {
				return fmt.Errorf("read client ca: %w", err)
			}
			if ok := pool.AppendCertsFromPEM(b); !ok {
				return fmt.Errorf("invalid client ca pem")
			}
		}
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  pool,
		}
	}

	httpServer := &http.Server{
		Addr:      cfg.HTTPAddr,
		Handler:   srv.Handler(),
		TLSConfig: tlsCfg,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if cfg.InsecureHTTP {
		log.Printf("control-plane listening on http://%s", cfg.HTTPAddr)
		return httpServer.ListenAndServe()
	}
	log.Printf("control-plane listening on https://%s", cfg.HTTPAddr)
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("tls cert/key required")
	}
	return httpServer.ListenAndServeTLS(certFile, keyFile)
}
