package config

import (
	"fmt"
	"os"
	"strconv"
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
	DevBearerAdmin      string
	DevBearerOperator   string
	DevBearerViewer     string
	BastionHost         string
	NodeCertTTL         time.Duration
	SessionTTL          time.Duration
	HeartbeatOfflineSec int
	DBTimeoutSec        int
	EnrollRatePerMinute int
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
		DevBearerAdmin:      getenv("DEV_BEARER_ADMIN", "dev-admin"),
		DevBearerOperator:   getenv("DEV_BEARER_OPERATOR", "dev-operator"),
		DevBearerViewer:     getenv("DEV_BEARER_VIEWER", "dev-viewer"),
		BastionHost:         getenv("BASTION_HOST", "bastion.internal"),
		NodeCertTTL:         getenvDuration("NODE_CERT_TTL", 168*time.Hour),
		SessionTTL:          getenvDuration("SESSION_TTL", 30*time.Minute),
		HeartbeatOfflineSec: getenvInt("HEARTBEAT_OFFLINE_SEC", 60),
		DBTimeoutSec:        getenvInt("DB_TIMEOUT_SEC", 5),
		EnrollRatePerMinute: getenvInt("ENROLL_RATE_PER_MINUTE", 30),
	}

	if cfg.HTTPAddr == "" {
		return Config{}, fmt.Errorf("HTTP_ADDR must not be empty")
	}
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
