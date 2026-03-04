package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"astrality/internal/auth"

	"github.com/jackc/pgx/v5"
)

type createJobReq struct {
	NodeSelector string   `json:"node_selector"`
	Command      string   `json:"command"`
	Args         []string `json:"args"`
	TimeoutSec   int      `json:"timeout_sec"`
	MaxRetries   int      `json:"max_retries"`
}

type updateAllowlistReq struct {
	Commands []string `json:"commands"`
}

type jobResultReq struct {
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

func (s *Server) handleV2Jobs(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := s.store.ListJobs(r.Context(), limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		if !auth.HasRole(p.Role, "operator") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req createJobReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Command = strings.TrimSpace(req.Command)
		if req.Command == "" {
			writeErr(w, http.StatusBadRequest, "command is required")
			return
		}
		policy, err := s.store.GetAllowlistPolicy(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !isCommandAllowed(req.Command, policy.Commands) {
			writeErr(w, http.StatusBadRequest, "command not allowed")
			return
		}
		job, err := s.store.CreateJob(r.Context(), req.NodeSelector, req.Command, req.Args, req.TimeoutSec, req.MaxRetries, p.Subject)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "job.created", "", map[string]any{"job_id": job.ID, "command": job.Command})
		writeJSON(w, http.StatusCreated, job)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleV2JobSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v2/jobs/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	jobID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		job, runs, err := s.store.GetJob(r.Context(), jobID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "job not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"job": job, "runs": runs})
		return
	}

	switch parts[1] {
	case "runs":
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_, runs, err := s.store.GetJob(r.Context(), jobID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "job not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": runs})
	case "cancel":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !auth.HasRole(p.Role, "operator") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		if err := s.store.CancelJob(r.Context(), jobID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "job.canceled", "", map[string]any{"job_id": jobID})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleV2Allowlist(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	switch r.Method {
	case http.MethodGet:
		policy, err := s.store.GetAllowlistPolicy(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, policy)
	case http.MethodPut:
		if !auth.HasRole(p.Role, "admin") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req updateAllowlistReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		commands := normalizeCommands(req.Commands)
		if len(commands) == 0 {
			writeErr(w, http.StatusBadRequest, "commands required")
			return
		}
		if err := s.store.UpdateAllowlistPolicy(r.Context(), commands, p.Subject); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "policy.updated", "", map[string]any{"policy": "allowlist"})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "commands": commands})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleV2AgentNextJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID, err := s.authenticateAgent(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	task, err := s.store.ClaimNextJobRun(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = s.store.InsertAudit(r.Context(), "agent:"+nodeID, "job.claimed", nodeID, map[string]any{"job_id": task.JobID, "run_id": task.RunID})
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) handleV2AgentJobSubroutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	nodeID, err := s.authenticateAgent(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v2/agent/jobs/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 || parts[1] != "result" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	runID := parts[0]

	var req jobResultReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Status != "succeeded" && req.Status != "failed" && req.Status != "timed_out" {
		writeErr(w, http.StatusBadRequest, "invalid status")
		return
	}
	startedAt := time.Now().UTC()
	finishedAt := time.Now().UTC()
	if req.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339, req.StartedAt); err == nil {
			startedAt = t
		}
	}
	if req.FinishedAt != "" {
		if t, err := time.Parse(time.RFC3339, req.FinishedAt); err == nil {
			finishedAt = t
		}
	}
	if err := s.store.CompleteJobRun(r.Context(), nodeID, runID, req.Status, req.ExitCode, req.Stdout, req.Stderr, startedAt, finishedAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = s.store.InsertAudit(r.Context(), "agent:"+nodeID, "job.finished", nodeID, map[string]any{"run_id": runID, "status": req.Status})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func normalizeCommands(commands []string) []string {
	uniq := map[string]struct{}{}
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		v := strings.TrimSpace(c)
		if v == "" {
			continue
		}
		if _, ok := uniq[v]; ok {
			continue
		}
		uniq[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func isCommandAllowed(command string, allowlist []string) bool {
	for _, c := range allowlist {
		if command == strings.TrimSpace(c) {
			return true
		}
	}
	return false
}
