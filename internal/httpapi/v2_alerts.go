package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"astrality/internal/auth"
	"astrality/internal/db"
)

type alertRuleReq struct {
	Name        string         `json:"name"`
	QueryType   string         `json:"query_type"`
	QueryConfig map[string]any `json:"query_config"`
	Severity    string         `json:"severity"`
	Enabled     bool           `json:"enabled"`
	CooldownSec int            `json:"cooldown_sec"`
	ChannelIDs  []string       `json:"channel_ids"`
}

type muteReq struct {
	DurationSec int `json:"duration_sec"`
}

type notificationEndpointReq struct {
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Config  map[string]any `json:"config"`
	Enabled bool           `json:"enabled"`
}

func (s *Server) handleV2AlertRules(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.ListAlertRules(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": rules})
	case http.MethodPost:
		if !auth.HasRole(p.Role, "admin") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req alertRuleReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.QueryType = strings.TrimSpace(req.QueryType)
		req.Severity = strings.TrimSpace(req.Severity)
		if req.Name == "" || req.QueryType == "" || req.Severity == "" {
			writeErr(w, http.StatusBadRequest, "name/query_type/severity required")
			return
		}
		rule, err := s.store.CreateAlertRule(r.Context(), db.AlertRule{
			Name:        req.Name,
			QueryType:   req.QueryType,
			QueryConfig: req.QueryConfig,
			Severity:    req.Severity,
			Enabled:     req.Enabled,
			CooldownSec: req.CooldownSec,
			ChannelIDs:  req.ChannelIDs,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "alert.rule.created", "", map[string]any{"rule_id": rule.ID})
		writeJSON(w, http.StatusCreated, rule)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleV2AlertRuleSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v2/alerts/rules/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	ruleID := parts[0]

	if len(parts) == 1 {
		if r.Method != http.MethodPut {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !auth.HasRole(p.Role, "admin") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req alertRuleReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		err := s.store.UpdateAlertRule(r.Context(), ruleID, db.AlertRule{
			Name:        strings.TrimSpace(req.Name),
			QueryType:   strings.TrimSpace(req.QueryType),
			QueryConfig: req.QueryConfig,
			Severity:    strings.TrimSpace(req.Severity),
			Enabled:     req.Enabled,
			CooldownSec: req.CooldownSec,
			ChannelIDs:  req.ChannelIDs,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "alert.rule.updated", "", map[string]any{"rule_id": ruleID})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	switch parts[1] {
	case "mute":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !auth.HasRole(p.Role, "operator") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		var req muteReq
		_ = decodeJSON(r.Body, &req)
		if req.DurationSec <= 0 {
			req.DurationSec = 3600
		}
		until := time.Now().Add(time.Duration(req.DurationSec) * time.Second)
		if err := s.store.MuteAlertRule(r.Context(), ruleID, until); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "alert.rule.muted", "", map[string]any{"rule_id": ruleID})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mute_until": until.UTC()})
	case "unmute":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !auth.HasRole(p.Role, "operator") {
			writeErr(w, http.StatusForbidden, "insufficient role")
			return
		}
		if err := s.store.UnmuteAlertRule(r.Context(), ruleID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "alert.rule.unmuted", "", map[string]any{"rule_id": ruleID})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleV2AlertEvents(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	items, err := s.store.ListAlertEvents(r.Context(), limit, status, severity)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleV2AlertEventSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v2/alerts/events/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 || parts[1] != "ack" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !auth.HasRole(p.Role, "operator") {
		writeErr(w, http.StatusForbidden, "insufficient role")
		return
	}
	if err := s.store.AckAlertEvent(r.Context(), parts[0]); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = s.store.InsertAudit(r.Context(), p.Subject, "alert.event.ack", "", map[string]any{"event_id": parts[0]})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleV2NotificationEndpoints(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListNotificationEndpoints(r.Context())
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
		var req notificationEndpointReq
		if err := decodeJSON(r.Body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		ep, err := s.store.CreateNotificationEndpoint(r.Context(), db.NotificationEndpoint{
			Name:    strings.TrimSpace(req.Name),
			Type:    strings.TrimSpace(req.Type),
			Config:  req.Config,
			Enabled: req.Enabled,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		_ = s.store.InsertAudit(r.Context(), p.Subject, "notification.endpoint.created", "", map[string]any{"endpoint_id": ep.ID})
		writeJSON(w, http.StatusCreated, ep)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleV2NotificationEndpointSubroutes(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if r.Method != http.MethodPut {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !auth.HasRole(p.Role, "admin") {
		writeErr(w, http.StatusForbidden, "insufficient role")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v2/notifications/endpoints/")
	id = strings.TrimSpace(strings.Trim(id, "/"))
	if id == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var req notificationEndpointReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.store.UpdateNotificationEndpoint(r.Context(), id, db.NotificationEndpoint{
		Name:    strings.TrimSpace(req.Name),
		Type:    strings.TrimSpace(req.Type),
		Config:  req.Config,
		Enabled: req.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = s.store.InsertAudit(r.Context(), p.Subject, "notification.endpoint.updated", "", map[string]any{"endpoint_id": id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleV2SLOSnapshots(w http.ResponseWriter, r *http.Request, p auth.Principal) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListSLOSnapshots(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
