package httpapi

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"astrality/internal/auth"
	"astrality/internal/db"

	"github.com/gorilla/websocket"
)

type createConsoleSessionReq struct {
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

type createRunbookTemplateReq struct {
	Name        string              `json:"name"`
	TriggerTags []string            `json:"trigger_tags"`
	Steps       []db.RunbookStepDef `json:"steps"`
}

type executeRunbookReq struct {
	IncidentID string `json:"incident_id"`
}

func (s *Server) handleV2ConsoleSessions(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := s.store.ListConsoleSessions(r.Context(), limit)
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
		var req createConsoleSessionReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.NodeID == "" || req.Reason == "" {
			writeErr(w, http.StatusBadRequest, "node_id and reason are required")
			return
		}
		if _, _, err := s.store.GetNode(r.Context(), req.NodeID, time.Duration(s.cfg.HeartbeatOfflineSec)*time.Second); err != nil {
			writeErr(w, http.StatusNotFound, "node not found")
			return
		}
		token := randomToken(64)
		session, err := s.store.CreateConsoleSession(r.Context(), req.NodeID, p.Subject, req.Reason, db.HashToken(token), time.Now().Add(1*time.Hour))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "console.live.created", req.NodeID, map[string]any{"session_id": session.ID, "reason": req.Reason})
		_ = s.store.InsertTimelineEvent(r.Context(), "console_session", req.NodeID, "info", p.Subject, "console session opened", map[string]any{"session_id": session.ID, "reason": req.Reason})
		writeJSON(w, http.StatusCreated, map[string]any{
			"session":       session,
			"session_token": token,
			"ws_url":        "/api/v2/console/ws/" + session.ID + "?token=" + token,
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleV2ConsoleSessionSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v2/console/sessions/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	sessionID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		session, err := s.store.GetConsoleSession(r.Context(), sessionID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "session not found")
			return
		}
		writeJSON(w, http.StatusOK, session)
		return
	}
	switch parts[1] {
	case "close":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !auth.HasRole(p.Role, "operator") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		if err := s.store.CloseConsoleSession(r.Context(), sessionID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "console.live.closed", "", map[string]any{"session_id": sessionID})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "replay":
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, hasMore, err := s.store.ListConsoleReplay(r.Context(), sessionID, offset, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "items": items, "has_more": hasMore})
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (s *Server) handleV2ConsoleWS(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/v2/console/ws/")
	sessionID = strings.Trim(strings.TrimSpace(sessionID), "/")
	if sessionID == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	session, err := s.store.ValidateConsoleSessionToken(r.Context(), sessionID, db.HashToken(token))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	node, _, err := s.store.GetNode(r.Context(), session.NodeID, time.Duration(s.cfg.HeartbeatOfflineSec)*time.Second)
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	sshTarget := "root@" + node.IP
	cmd := exec.CommandContext(ctx, "ssh", "-tt", "-o", "StrictHostKeyChecking=no", "-J", s.cfg.BastionHost, sshTarget)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		_ = conn.WriteJSON(map[string]any{"error": err.Error()})
		return
	}

	_ = s.store.MarkConsoleSessionActive(r.Context(), sessionID)
	_ = s.store.InsertTimelineEvent(r.Context(), "console_ws", session.NodeID, "info", session.OpenedBy, "console ws connected", map[string]any{"session_id": sessionID})

	var writeMu sync.Mutex
	send := func(data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, data)
	}

	copyPipe := func(stream string, reader io.Reader, done chan<- struct{}) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 1024)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				_ = s.store.AppendConsoleFrame(r.Context(), sessionID, stream, base64.StdEncoding.EncodeToString(chunk))
				_ = send(chunk)
			}
			if err != nil {
				return
			}
		}
	}

	doneCh := make(chan struct{}, 2)
	go copyPipe("stdout", stdout, doneCh)
	go copyPipe("stderr", stderr, doneCh)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if len(msg) > 0 {
			_, _ = stdin.Write(msg)
			_ = s.store.AppendConsoleFrame(r.Context(), sessionID, "stdin", base64.StdEncoding.EncodeToString(msg))
		}
	}

	cancel()
	_ = stdin.Close()
	_ = cmd.Process.Kill()
	_, _ = <-doneCh, <-doneCh
	_ = cmd.Wait()
	_ = s.store.CloseConsoleSession(r.Context(), sessionID)
	_ = s.store.InsertTimelineEvent(r.Context(), "console_ws", session.NodeID, "info", session.OpenedBy, "console ws closed", map[string]any{"session_id": sessionID})
}

func (s *Server) handleV2IncidentTimeline(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	var from *time.Time
	var to *time.Time
	if v := strings.TrimSpace(r.URL.Query().Get("from")); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = &t
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("to")); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = &t
		}
	}
	items, err := s.store.ListTimelineEvents(r.Context(), nodeID, severity, from, to, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleV2Runbooks(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListRunbookTemplates(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		if !auth.HasRole(p.Role, "admin") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req createRunbookTemplateReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		created, err := s.store.CreateRunbookTemplate(r.Context(), db.RunbookTemplate{
			Name:        strings.TrimSpace(req.Name),
			TriggerTags: req.TriggerTags,
			Steps:       req.Steps,
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleV2RunbookSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v2/runbooks/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	if parts[0] == "executions" {
		if len(parts) == 2 && r.Method == http.MethodGet {
			exec, err := s.store.GetRunbookExecution(r.Context(), parts[1])
			if err != nil {
				writeErr(w, http.StatusNotFound, "execution not found")
				return
			}
			writeJSON(w, http.StatusOK, exec)
			return
		}
		if len(parts) == 5 && parts[2] == "step" && parts[4] == "confirm" && r.Method == http.MethodPost {
			if !auth.HasRole(p.Role, "operator") {
				writeErr(w, http.StatusForbidden, "insufficient role")
				return
			}
			if err := s.store.ConfirmRunbookStep(r.Context(), parts[1], parts[3], p.Subject); err != nil {
				writeErr(w, http.StatusInternalServerError, "internal error")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	if len(parts) == 2 && parts[1] == "execute" && r.Method == http.MethodPost {
		if !auth.HasRole(p.Role, "operator") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req executeRunbookReq
		_ = decodeJSON(r.Body, &req)
		exec, err := s.store.StartRunbookExecution(r.Context(), parts[0], strings.TrimSpace(req.IncidentID), p.Subject)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, exec)
		return
	}

	writeErr(w, http.StatusNotFound, "not found")
}
