package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr            string
	InsecureHTTP        bool
	TLSCertFile         string
	TLSKeyFile          string
	ClientCAFile        string
	DataDir             string
	DBURL               string
	OIDCIssuer          string
	OIDCAudience        string
	OIDCClientSecret    string
	DevBearerAdmin      string
	DevBearerOperator   string
	DevBearerViewer     string
	BastionHost         string
	ConsoleSSHUser      string
	ConsoleSSHUsers     []string
	ConsoleSSHKeyFile   string
	ConsoleTargetOrder  []string
	NodeCertTTL         time.Duration
	SessionTTL          time.Duration
	HeartbeatOfflineSec int
	DBTimeoutSec        int
	EnrollRatePerMinute int
	LoginRatePerMinute  int
	AlertEvalSec        int
	NotifyScanSec       int
	WebhookHMACSecret   string
	SMTPHost            string
	SMTPPort            int
	SMTPUser            string
	SMTPPass            string
	SMTPFrom            string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:            getenv("HTTP_ADDR", ":8443"),
		InsecureHTTP:        getenvBool("DEV_INSECURE_HTTP", false),
		TLSCertFile:         os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:          os.Getenv("TLS_KEY_FILE"),
		ClientCAFile:        os.Getenv("CLIENT_CA_FILE"),
		DataDir:             getenv("DATA_DIR", "./data"),
		DBURL:               getenv("DATABASE_URL", "postgres://astrality:astrality@localhost:5432/astrality?sslmode=disable"),
		OIDCIssuer:          os.Getenv("OIDC_ISSUER"),
		OIDCAudience:        os.Getenv("OIDC_AUDIENCE"),
		OIDCClientSecret:    os.Getenv("OIDC_CLIENT_SECRET"),
		DevBearerAdmin:      getenv("DEV_BEARER_ADMIN", "dev-admin"),
		DevBearerOperator:   getenv("DEV_BEARER_OPERATOR", "dev-operator"),
		DevBearerViewer:     getenv("DEV_BEARER_VIEWER", "dev-viewer"),
		BastionHost:         strings.TrimSpace(os.Getenv("BASTION_HOST")),
		ConsoleSSHUser:      getenv("CONSOLE_SSH_USER", "root"),
		ConsoleSSHUsers:     parseCSV(getenv("CONSOLE_SSH_USERS", "")),
		ConsoleSSHKeyFile:   strings.TrimSpace(os.Getenv("CONSOLE_SSH_KEY_FILE")),
		ConsoleTargetOrder:  parseCSV(getenv("CONSOLE_TARGET_ORDER", "ip,hostname")),
		NodeCertTTL:         getenvDuration("NODE_CERT_TTL", 168*time.Hour),
		SessionTTL:          getenvDuration("SESSION_TTL", 30*time.Minute),
		HeartbeatOfflineSec: getenvInt("HEARTBEAT_OFFLINE_SEC", 60),
		DBTimeoutSec:        getenvInt("DB_TIMEOUT_SEC", 5),
		EnrollRatePerMinute: getenvInt("ENROLL_RATE_PER_MINUTE", 30),
		LoginRatePerMinute:  getenvInt("LOGIN_RATE_PER_MINUTE", 20),
		AlertEvalSec:        getenvInt("ALERT_EVAL_SEC", 30),
		NotifyScanSec:       getenvInt("NOTIFY_SCAN_SEC", 5),
		WebhookHMACSecret:   getenv("WEBHOOK_HMAC_SECRET", ""),
		SMTPHost:            getenv("SMTP_HOST", ""),
		SMTPPort:            getenvInt("SMTP_PORT", 587),
		SMTPUser:            getenv("SMTP_USER", ""),
		SMTPPass:            getenv("SMTP_PASS", ""),
		SMTPFrom:            getenv("SMTP_FROM", "astrality@localhost"),
	}

	if cfg.HTTPAddr == "" {
		return Config{}, fmt.Errorf("HTTP_ADDR must not be empty")
	}
	if len(cfg.ConsoleSSHUsers) == 0 {
		cfg.ConsoleSSHUsers = []string{strings.TrimSpace(cfg.ConsoleSSHUser)}
	}
	if len(cfg.ConsoleSSHUsers) == 0 || cfg.ConsoleSSHUsers[0] == "" {
		cfg.ConsoleSSHUsers = []string{"root"}
	}
	validTargets := make([]string, 0, len(cfg.ConsoleTargetOrder))
	for _, t := range cfg.ConsoleTargetOrder {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "ip", "hostname":
			validTargets = append(validTargets, strings.ToLower(strings.TrimSpace(t)))
		}
	}
	if len(validTargets) == 0 {
		validTargets = []string{"ip", "hostname"}
	}
	cfg.ConsoleTargetOrder = validTargets
	return cfg, nil
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func getenvBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
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

func getenvDuration(k string, d time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	dur, err := time.ParseDuration(v)
	if err != nil {
		return d
	}
	return dur
}

func parseCSV(raw string) []string {
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
