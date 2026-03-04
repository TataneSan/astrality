package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type authConfigResp struct {
	Enabled  bool   `json:"enabled"`
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

type authLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authRefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type oidcTokenResp struct {
	AccessToken  string `json:"access_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type oidcErrorResp struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.TrimSpace(s.cfg.OIDCIssuer) == "" {
		writeJSON(w, http.StatusOK, authConfigResp{Enabled: false})
		return
	}
	writeJSON(w, http.StatusOK, authConfigResp{
		Enabled:  true,
		Issuer:   strings.TrimSpace(s.cfg.OIDCIssuer),
		ClientID: strings.TrimSpace(s.cfg.OIDCAudience),
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.TrimSpace(s.cfg.OIDCIssuer) == "" {
		writeErr(w, http.StatusBadRequest, "oidc not configured")
		return
	}
	var req authLoginReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.loginRL.Allow(remoteIP(r.RemoteAddr)) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password are required")
		return
	}
	clientID := strings.TrimSpace(s.cfg.OIDCAudience)
	if clientID == "" {
		writeErr(w, http.StatusInternalServerError, "oidc client_id not configured")
		return
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", clientID)
	if v := strings.TrimSpace(s.cfg.OIDCClientSecret); v != "" {
		form.Set("client_secret", v)
	}
	form.Set("username", req.Username)
	form.Set("password", req.Password)
	form.Set("scope", "openid profile email")

	out, status, err := s.exchangeOIDCToken(r.Context(), form)
	if err != nil {
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.TrimSpace(s.cfg.OIDCIssuer) == "" {
		writeErr(w, http.StatusBadRequest, "oidc not configured")
		return
	}
	var req authRefreshReq
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	clientID := strings.TrimSpace(s.cfg.OIDCAudience)
	if clientID == "" {
		writeErr(w, http.StatusInternalServerError, "oidc client_id not configured")
		return
	}
	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		writeErr(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	if v := strings.TrimSpace(s.cfg.OIDCClientSecret); v != "" {
		form.Set("client_secret", v)
	}
	form.Set("refresh_token", req.RefreshToken)
	form.Set("scope", "openid profile email")

	out, status, err := s.exchangeOIDCToken(r.Context(), form)
	if err != nil {
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) exchangeOIDCToken(ctx context.Context, form url.Values) (oidcTokenResp, int, error) {
	endpoint, err := s.oidcTokenEndpoint(ctx)
	if err != nil {
		return oidcTokenResp{}, http.StatusBadGateway, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResp{}, http.StatusBadGateway, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return oidcTokenResp{}, http.StatusBadGateway, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var oe oidcErrorResp
		_ = json.Unmarshal(raw, &oe)
		msg := strings.TrimSpace(oe.ErrorDescription)
		if msg == "" {
			msg = strings.TrimSpace(oe.Error)
		}
		if strings.EqualFold(strings.TrimSpace(oe.Error), "invalid_grant") {
			msg = "invalid credentials"
		}
		if msg == "" {
			msg = "oidc token exchange failed"
		}
		status := http.StatusBadGateway
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			status = http.StatusUnauthorized
		}
		return oidcTokenResp{}, status, fmt.Errorf("%s", msg)
	}

	var out oidcTokenResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return oidcTokenResp{}, http.StatusBadGateway, err
	}
	if strings.TrimSpace(out.IDToken) == "" && strings.TrimSpace(out.AccessToken) == "" {
		return oidcTokenResp{}, http.StatusBadGateway, fmt.Errorf("missing token from oidc provider")
	}
	return out, http.StatusOK, nil
}

func (s *Server) oidcTokenEndpoint(ctx context.Context) (string, error) {
	if strings.TrimSpace(s.cfg.OIDCIssuer) == "" {
		return "", fmt.Errorf("oidc issuer is empty")
	}

	s.oidcMu.RLock()
	cached := s.oidcTEP
	s.oidcMu.RUnlock()
	if cached != "" {
		return cached, nil
	}

	issuer := strings.TrimRight(strings.TrimSpace(s.cfg.OIDCIssuer), "/")
	wellKnown := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("oidc discovery status %d", resp.StatusCode)
	}
	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", err
	}
	doc.TokenEndpoint = strings.TrimSpace(doc.TokenEndpoint)
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("token_endpoint missing from discovery")
	}

	s.oidcMu.Lock()
	s.oidcTEP = doc.TokenEndpoint
	s.oidcMu.Unlock()
	return doc.TokenEndpoint, nil
}
