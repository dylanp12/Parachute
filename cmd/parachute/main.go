package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/config"
	"github.com/parachute-security/parachute/internal/dashboard"
	"github.com/parachute-security/parachute/internal/metrics"
	"github.com/parachute-security/parachute/internal/middleware"
	"github.com/parachute-security/parachute/internal/proxy"
	"github.com/parachute-security/parachute/internal/relay"
	"github.com/parachute-security/parachute/internal/storage"
)

var (
	version     = "dev"
	configPath  = flag.String("config", "/etc/parachute/config.yaml", "Path to config file")
	showVersion = flag.Bool("version", false, "Show version and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("Parachute %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Check authentication configuration
	authConfigured := cfg.Auth.Username != "" || cfg.Auth.Token != ""
	if !authConfigured {
		if cfg.Auth.AllowInsecure {
			log.Warn("Running in INSECURE mode without authentication!")
			log.Warn("This should only be used for development.")
		} else {
			log.Fatal("No authentication configured and allow_insecure is not set.")
		}
	}

	log.Infof("Starting Parachute %s", version)
	log.Infof("Upstream: %s", cfg.Upstream)
	log.Infof("Listen: %s", cfg.Listen)
	log.Infof("Forward Proxy: %s", cfg.ProxyListen)
	log.Infof("Storage: %s", cfg.Storage.Type)

	// Initialize storage and approval queue
	var approvalQ *approval.Queue
	var store *storage.Store

	if cfg.Storage.Type == "sqlite" {
		// Ensure storage directory exists
		storageDir := filepath.Dir(cfg.Storage.Path)
		if err := os.MkdirAll(storageDir, 0755); err != nil {
			log.Fatalf("Failed to create storage directory: %v", err)
		}

		store, err = storage.NewStore(cfg.Storage.Path)
		if err != nil {
			log.Fatalf("Failed to initialize storage: %v", err)
		}
		log.Infof("Using SQLite storage: %s", cfg.Storage.Path)
		approvalQ = approval.NewPersistentQueue(5*time.Minute, store)
	} else {
		log.Info("Using in-memory storage (approvals will not persist across restarts)")
		approvalQ = approval.NewQueue(5 * time.Minute)
	}

	webhooks := loadWebhooks(cfg)
	notifier := approval.NewNotifier(webhooks)

	// Create rate limiter: 60 requests per minute per IP
	rateLimiter := middleware.NewRateLimiter(60, time.Minute)

	app := fiber.New(fiber.Config{
		AppName:        "Parachute",
		ServerHeader:   "Parachute",
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		ReadBufferSize: 16384,
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(middleware.StripForwardedHeaders()) // Strip/overwrite X-Forwarded-* headers for security
	app.Use(middleware.SecureHeaders())          // Add security headers (X-Frame-Options, etc.)
	app.Use(middleware.CorrelationID())          // Add correlation ID to all requests
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"}, // Wildcard for development; set specific origins in production
	}))

	// Health check and metrics endpoints - no auth required
	app.Get("/health", proxy.HealthHandler())
	app.Get("/healthz", proxy.HealthHandler()) // Kubernetes-style alias
	app.Get("/version", proxy.VersionHandler(version))
	app.Get("/metrics", metrics.Handler()) // Prometheus metrics

	// Dashboard routes - auth required
	dashboardGroup := app.Group("/dashboard")
	dashboardGroup.Use(rateLimiter.Handler())
	dashboardGroup.Use(middleware.Auth(&cfg.Auth))
	dashboardGroup.Get("/*", dashboard.Handler())

	// API routes - auth required with rate limiting
	apiGroup := app.Group("/api")
	apiGroup.Use(rateLimiter.Handler())
	apiGroup.Use(middleware.Auth(&cfg.Auth))
	dashboard.APIRoutes(apiGroup, approvalQ)

	// Proxy routes - auth required
	proxyHandler := proxy.New(cfg, approvalQ, notifier)
	proxyGroup := app.Group("/proxy")
	proxyGroup.Use(middleware.Auth(&cfg.Auth))
	proxyGroup.All("/*", proxyHandler.Handler())

	// Cloud relay (Phase 3)
	if cfg.Relay.Enabled {
		relayClient := relay.New(&cfg.Relay, approvalQ)
		go relayClient.Start(context.Background())
	}

	// Start forward proxy for agent egress control
	proxyServer := proxy.NewProxyServer(cfg)
	go func() {
		if err := proxyServer.ListenAndServe(cfg.ProxyListen); err != nil {
			log.Errorf("Forward proxy error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := app.Listen(cfg.Listen); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	log.Infof("Server started on %s", cfg.Listen)
	log.Infof("Forward proxy started on %s", cfg.ProxyListen)
	log.Infof("Dashboard: http://localhost%s/dashboard/", cfg.Listen)

	<-ctx.Done()
	log.Info("Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := proxyServer.Close(); err != nil {
		log.Errorf("Forward proxy shutdown error: %v", err)
	}

	if store != nil {
		if err := store.Close(); err != nil {
			log.Errorf("Storage shutdown error: %v", err)
		}
	}

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Errorf("Shutdown error: %v", err)
	}

	log.Info("Goodbye!")
}

// loadWebhooks loads webhook configurations from config.
// Currently returns empty list - webhook configuration via config file planned for v1.1.
func loadWebhooks(cfg *config.Config) []approval.WebhookConfig {
	return []approval.WebhookConfig{}
}
