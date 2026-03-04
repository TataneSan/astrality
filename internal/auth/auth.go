package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"astrality/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Principal struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
}

type Authenticator struct {
	verifier        *oidc.IDTokenVerifier
	devBearerAdmin  string
	devBearerOper   string
	devBearerViewer string
}

type claims struct {
	Sub           string   `json:"sub"`
	PreferredUser string   `json:"preferred_username"`
	Role          string   `json:"role"`
	Roles         []string `json:"roles"`
	RealmAccess   struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

func New(ctx context.Context, cfg config.Config) (*Authenticator, error) {
	a := &Authenticator{
		devBearerAdmin:  cfg.DevBearerAdmin,
		devBearerOper:   cfg.DevBearerOperator,
		devBearerViewer: cfg.DevBearerViewer,
	}

	if cfg.OIDCIssuer == "" {
		return a, nil
	}
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("init oidc provider: %w", err)
	}
	a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDCAudience})
	return a, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, authorization string) (Principal, error) {
	token, err := parseBearer(authorization)
	if err != nil {
		return Principal{}, err
	}

	if a.verifier == nil {
		switch token {
		case a.devBearerAdmin:
			return Principal{Subject: "dev-admin", Role: "admin"}, nil
		case a.devBearerOper:
			return Principal{Subject: "dev-operator", Role: "operator"}, nil
		case a.devBearerViewer:
			return Principal{Subject: "dev-viewer", Role: "viewer"}, nil
		default:
			return Principal{}, errors.New("invalid dev bearer")
		}
	}

	idToken, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return Principal{}, fmt.Errorf("verify oidc token: %w", err)
	}
	var c claims
	if err := idToken.Claims(&c); err != nil {
		return Principal{}, fmt.Errorf("decode oidc claims: %w", err)
	}

	subject := c.Sub
	if c.PreferredUser != "" {
		subject = c.PreferredUser
	}
	role := pickRole(c)
	return Principal{Subject: subject, Role: role}, nil
}

func parseBearer(authorization string) (string, error) {
	if authorization == "" {
		return "", errors.New("missing authorization header")
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", errors.New("invalid authorization header")
	}
	return strings.TrimSpace(parts[1]), nil
}

func pickRole(c claims) string {
	roles := make([]string, 0, len(c.Roles)+len(c.RealmAccess.Roles)+1)
	if c.Role != "" {
		roles = append(roles, strings.ToLower(c.Role))
	}
	for _, r := range c.Roles {
		roles = append(roles, strings.ToLower(r))
	}
	for _, r := range c.RealmAccess.Roles {
		roles = append(roles, strings.ToLower(r))
	}
	for _, r := range roles {
		if r == "admin" {
			return "admin"
		}
	}
	for _, r := range roles {
		if r == "operator" {
			return "operator"
		}
	}
	return "viewer"
}

func HasRole(actual string, required string) bool {
	order := map[string]int{"viewer": 1, "operator": 2, "admin": 3}
	return order[actual] >= order[required]
}
