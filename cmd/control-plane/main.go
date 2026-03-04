package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"astrality/internal/alerting"
	"astrality/internal/auth"
	"astrality/internal/config"
	"astrality/internal/db"
	"astrality/internal/enroll"
	"astrality/internal/httpapi"
	"astrality/internal/metrics"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	store, err := db.Connect(ctx, cfg.DBURL)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		log.Fatalf("db migrate: %v", err)
	}

	authn, err := auth.New(ctx, cfg)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}

	ca, err := enroll.EnsureCA(cfg.DataDir)
	if err != nil {
		log.Fatalf("init ca: %v", err)
	}

	certFile := cfg.TLSCertFile
	keyFile := cfg.TLSKeyFile
	if !cfg.InsecureHTTP && (certFile == "" || keyFile == "") {
		hostname, _ := os.Hostname()
		certFile, keyFile, err = ca.EnsureServerCert(cfg.DataDir, []string{"localhost", hostname, "127.0.0.1"})
		if err != nil {
			log.Fatalf("ensure server cert: %v", err)
		}
	}

	m := metrics.New()
	server := httpapi.New(cfg, store, authn, ca, m)
	alertSvc := alerting.New(cfg, store)
	alertSvc.Start(ctx)

	go func() {
		<-ctx.Done()
		time.Sleep(100 * time.Millisecond)
	}()

	if err := httpapi.Run(ctx, cfg, server, certFile, keyFile); err != nil && !strings.Contains(err.Error(), "Server closed") {
		log.Fatalf("server exited: %v", err)
	}
}
