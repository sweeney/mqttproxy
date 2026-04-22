package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/sweeney/mqttproxy/internal/acl"
	"github.com/sweeney/mqttproxy/internal/config"
	"github.com/sweeney/mqttproxy/internal/jwks"
	"github.com/sweeney/mqttproxy/internal/jwt"
	"github.com/sweeney/mqttproxy/internal/proxy"
)

// version is set at build time via -ldflags "-X main.version=<git-sha>".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log, err := buildLogger(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	defer log.Sync()

	log.Info("starting mqttproxy",
		zap.String("listen", cfg.Listen.Addr),
		zap.String("broker", cfg.Broker.Addr),
	)

	jwksClient, err := jwks.NewClient(
		cfg.Auth.WellKnownURL,
		cfg.Auth.JWKSCacheTTL,
		&http.Client{Timeout: 10 * time.Second},
	)
	if err != nil {
		return fmt.Errorf("init JWKS client: %w", err)
	}

	// jwks.Client satisfies jwt.KeySource directly.
	validator, err := jwt.NewValidator(cfg.Auth.Issuer, cfg.Auth.Audience, jwksClient)
	if err != nil {
		return fmt.Errorf("init JWT validator: %w", err)
	}

	aclChecker := acl.NewChecker(cfg.ACL)
	dialer := proxy.NewTCPDialer(cfg.Broker.Addr, cfg.Broker.DialTimeout)

	handler := proxy.NewHandler(proxy.Config{
		Validator: validator,
		ACL:       aclChecker,
		Dialer:    dialer,
		Logger:    log,
	})

	brokerAddr := cfg.Broker.Addr

	mux := http.NewServeMux()
	mux.Handle(cfg.Listen.Path, handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		start := time.Now()
		conn, err := net.DialTimeout("tcp", brokerAddr, 3*time.Second)
		elapsed := time.Since(start)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "error",
				"version":    version,
				"broker":     brokerAddr,
				"detail":     err.Error(),
				"elapsed_ms": elapsed.Milliseconds(),
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
		conn.Close()
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"version":    version,
			"broker":     brokerAddr,
			"elapsed_ms": elapsed.Milliseconds(),
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
	})

	server := &http.Server{
		Addr:    cfg.Listen.Addr,
		Handler: mux,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info("listening", zap.String("addr", cfg.Listen.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("listen failed", zap.Error(err))
		}
	}()

	<-stop
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

func buildLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	switch level {
	case "debug":
		cfg.Level.SetLevel(zap.DebugLevel)
	case "warn":
		cfg.Level.SetLevel(zap.WarnLevel)
	case "error":
		cfg.Level.SetLevel(zap.ErrorLevel)
	default:
		cfg.Level.SetLevel(zap.InfoLevel)
	}
	return cfg.Build()
}
