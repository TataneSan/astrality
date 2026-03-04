package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"astrality/internal/config"
)

func TestHandleAuthConfigDisabled(t *testing.T) {
	s := New(config.Config{}, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/config", nil)
	rr := httptest.NewRecorder()

	s.handleAuthConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Enabled {
		t.Fatalf("expected enabled=false")
	}
}

func TestHandleAuthLoginNotConfigured(t *testing.T) {
	s := New(config.Config{}, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"u","password":"p"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleAuthLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleAuthRefreshNotConfigured(t *testing.T) {
	s := New(config.Config{}, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"r"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleAuthRefresh(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleAuthLoginRateLimit(t *testing.T) {
	cfg := config.Config{
		OIDCIssuer:         "http://127.0.0.1:1",
		OIDCAudience:       "astrality-ui",
		LoginRatePerMinute: 1,
	}
	s := New(cfg, nil, nil, nil, nil)

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"u","password":"p"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.RemoteAddr = "203.0.113.10:12345"
	rr1 := httptest.NewRecorder()
	s.handleAuthLogin(rr1, req1)
	if rr1.Code == http.StatusTooManyRequests {
		t.Fatalf("first request must not be rate-limited")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"u","password":"p"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "203.0.113.10:67890"
	rr2 := httptest.NewRecorder()
	s.handleAuthLogin(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second request, got %d", rr2.Code)
	}
}
