package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/parachute-security/parachute/internal/approval"
	"github.com/parachute-security/parachute/internal/config"
	"github.com/parachute-security/parachute/internal/dashboard"
	"github.com/parachute-security/parachute/internal/middleware"
	"github.com/parachute-security/parachute/internal/proxy"
	"github.com/parachute-security/parachute/internal/relay"
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

	log.Printf("Starting Parachute %s", version)
	log.Printf("Upstream: %s", cfg.Upstream)
	log.Printf("Listen: %s", cfg.Listen)

	approvalQ := approval.NewQueue(5 * time.Minute)
	webhooks := []approval.WebhookConfig{}
	notifier := approval.NewNotifier(webhooks)

	app := fiber.New(fiber.Config{
		AppName:        "Parachute",
		ServerHeader:   "Parachute",
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		ReadBufferSize: 16384, // Increase from default 4096 to prevent 431 errors
	})

	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path}\n",
	}))
	app.Use(cors.New())

	app.Get("/health", proxy.HealthHandler())

	dashboardGroup := app.Group("/dashboard")
	if cfg.Auth.Username != "" || cfg.Auth.Token != "" {
		dashboardGroup.Use(middleware.Auth(&cfg.Auth))
	}
	dashboardGroup.Get("/*", dashboard.Handler())

	apiGroup := app.Group("/api")
	if cfg.Auth.Username != "" || cfg.Auth.Token != "" {
		apiGroup.Use(middleware.Auth(&cfg.Auth))
	}
	dashboard.APIRoutes(apiGroup, approvalQ)

	proxyHandler := proxy.New(cfg, approvalQ, notifier)
	proxyGroup := app.Group("/proxy")
	if cfg.Auth.Username != "" || cfg.Auth.Token != "" {
		proxyGroup.Use(middleware.Auth(&cfg.Auth))
	}
	proxyGroup.All("/*", proxyHandler.Handler())

	if cfg.Relay.Enabled {
		relayClient := relay.New(&cfg.Relay, approvalQ)
		go relayClient.Start(context.Background())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := app.Listen(cfg.Listen); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	log.Printf("Server started on %s", cfg.Listen)
	log.Printf("Dashboard: http://localhost%s/dashboard/", cfg.Listen)

	<-ctx.Done()
	log.Println("Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Goodbye!")
}
