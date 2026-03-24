package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/dylanp12/parachute/internal/approval"
	"github.com/dylanp12/parachute/internal/broker"
	"github.com/dylanp12/parachute/internal/config"
	"github.com/dylanp12/parachute/internal/dashboard"
	"github.com/dylanp12/parachute/internal/interceptor"
	"github.com/dylanp12/parachute/internal/mcp"
	"github.com/dylanp12/parachute/internal/metrics"
	"github.com/dylanp12/parachute/internal/middleware"
	"github.com/dylanp12/parachute/internal/proxy"
	"github.com/dylanp12/parachute/internal/relay"
	"github.com/dylanp12/parachute/internal/storage"
	"github.com/dylanp12/parachute/internal/telemetry"
	"github.com/dylanp12/parachute/internal/telemetry/exporters"
	"github.com/dylanp12/parachute/pkg/integrations"
	"github.com/dylanp12/parachute/pkg/integrations/github"
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

	// M0: Reverse proxy tool interception deprecation
	if cfg.ReverseProxy.ToolInterception.Enabled {
		log.Warn("*** DEPRECATED: reverse_proxy.tool_interception is enabled.")
		log.Warn("*** This mode does NOT reliably intercept tool calls from WebSocket-based agents.")
		log.Warn("*** Migrate to the MCP gateway (mcp.enabled=true).")
	}

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Telemetry collector
	var collector *telemetry.Collector
	if cfg.Telemetry.Enabled {
		chainState, err := telemetry.LoadChainState(cfg.Telemetry.ChainStatePath)
		if err != nil {
			log.Fatalf("Failed to load chain state: %v", err)
		}

		var telemetryExporters []telemetry.Exporter
		jsonlExp, err := exporters.NewJSONLExporter(cfg.Telemetry.JSONL.Path)
		if err != nil {
			log.Fatalf("Failed to create JSONL exporter: %v", err)
		}
		telemetryExporters = append(telemetryExporters, jsonlExp)

		// Load SDR signing key
		var signingKey ed25519.PrivateKey
		var keyID string
		if cfg.Telemetry.Signing.KeyPath != "" {
			keyData, err := os.ReadFile(cfg.Telemetry.Signing.KeyPath)
			if err != nil {
				log.Fatalf("Failed to read signing key %s: %v", cfg.Telemetry.Signing.KeyPath, err)
			}

			// Try PEM decode first
			if block, _ := pem.Decode(keyData); block != nil {
				keyData = block.Bytes
			}

			switch len(keyData) {
			case ed25519.PrivateKeySize: // 64 bytes — full private key
				signingKey = ed25519.PrivateKey(keyData)
			case ed25519.SeedSize: // 32 bytes — seed
				signingKey = ed25519.NewKeyFromSeed(keyData)
			default:
				log.Fatalf("Invalid signing key size %d (expected 32 or 64 bytes)", len(keyData))
			}

			// Derive key ID
			pubKey := signingKey.Public().(ed25519.PublicKey)
			if cfg.Telemetry.Signing.KeyID != "" {
				keyID = cfg.Telemetry.Signing.KeyID
			} else {
				keyID = "sidecar/" + hex.EncodeToString(pubKey[:8])
			}
			log.Infof("SDR signing enabled: key_id=%s", keyID)
		} else {
			log.Info("SDR signing disabled: records will be unsigned")
		}

		collector = telemetry.NewCollector(telemetry.CollectorConfig{
			AgentID:        cfg.Telemetry.AgentID,
			TenantID:       cfg.Telemetry.TenantID,
			SidecarVersion: version,
			SigningKey:     signingKey,
			KeyID:          keyID,
		}, chainState, telemetryExporters)

		collector.Start(ctx)
		log.Infof("Telemetry enabled: JSONL -> %s", cfg.Telemetry.JSONL.Path)

		// HTTP batch exporter (when Pro URL configured)
		if cfg.Telemetry.HTTP.URL != "" {
			apiKey := os.Getenv(cfg.Telemetry.HTTP.APIKeyEnv)
			httpExp, err := exporters.NewHTTPBatchExporter(exporters.HTTPBatchConfig{
				ProURL:        cfg.Telemetry.HTTP.URL,
				APIKey:        apiKey,
				SpoolPath:     cfg.Telemetry.JSONL.Path,
				OffsetPath:    cfg.Telemetry.HTTP.OffsetPath,
				BatchSize:     cfg.Telemetry.HTTP.BatchSize,
				FlushInterval: parseDuration(cfg.Telemetry.HTTP.FlushInterval, 10*time.Second),
			})
			if err != nil {
				log.Fatalf("Failed to create HTTP exporter: %v", err)
			}
			httpExp.Start(ctx)
			log.Infof("Telemetry HTTP exporter -> %s", cfg.Telemetry.HTTP.URL)
		}

		// Heartbeat emitter
		if cfg.Telemetry.HTTP.URL != "" {
			heartbeatURL := strings.TrimSuffix(cfg.Telemetry.HTTP.URL, "/sdr-batch") + "/heartbeat"
			hb := exporters.NewHeartbeatEmitter(exporters.HeartbeatConfig{
				ProURL:   heartbeatURL,
				APIKey:   os.Getenv(cfg.Telemetry.HTTP.APIKeyEnv),
				AgentID:  cfg.Telemetry.AgentID,
				TenantID: cfg.Telemetry.TenantID,
				Interval: parseDuration(cfg.Telemetry.Heartbeat.Interval, 30*time.Second),
				Version:  version,
			})
			hb.Start(ctx)
		}
	}

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

	// MCP proxy (Model Context Protocol gateway)
	if cfg.MCP.Enabled {
		cmdInterceptor := interceptor.New(&cfg.RiskPolicy)
		mcpCfg := &mcp.ProxyConfig{
			Enabled:       cfg.MCP.Enabled,
			Listen:        cfg.MCP.Listen,
			DefaultPolicy: toMCPServerPolicy(cfg.MCP.DefaultPolicy),
			Servers:       toMCPServerPolicies(cfg.MCP.Servers),
			Upstreams:     toMCPUpstreams(cfg.MCP.Upstreams),
		}

		// MCP telemetry callback
		var mcpCallback func(mcp.TelemetryHook)
		if collector != nil {
			mcpCallback = func(event mcp.TelemetryHook) {
				te := telemetry.TelemetryEvent{
					ActionType:      event.ActionType,
					ActionTarget:    event.ActionTarget,
					Decision:        event.Decision,
					RulePath:        event.RulePath,
					EnforcementMode: event.EnforcementMode,
					SpanID:          event.SpanID,
					ParentSpanID:    event.ParentSpanID,
				}
				if event.Approval != nil {
					te.Approval = &telemetry.ApprovalDetail{
						ID:             event.Approval.ID,
						ApproverID:     event.Approval.ApproverID,
						ApproverType:   event.Approval.ApproverType,
						ApprovalSource: event.Approval.Source,
					}
				}
				collector.Record(te)
			}
		}
		mcpProxy := mcp.NewProxy(mcpCfg, approvalQ, notifier, cmdInterceptor, mcpCallback)
		mcpGroup := app.Group("/mcp")
		mcpGroup.Use(middleware.Auth(&cfg.Auth))
		mcpProxy.RegisterRoutes(mcpGroup)
		log.Infof("MCP proxy enabled on /mcp")
	}

	// Cloud relay (Phase 3)
	if cfg.Relay.Enabled {
		relayClient := relay.New(&cfg.Relay, approvalQ)
		go relayClient.Start(context.Background())
	}

	// Create egress telemetry callback
	var egressCallback func(string, string, string, string, string)
	if collector != nil {
		egressCallback = func(actionType, target, decision, rulePath, enforcementMode string) {
			collector.Record(telemetry.TelemetryEvent{
				ActionType:      actionType,
				ActionTarget:    target,
				Decision:        decision,
				RulePath:        rulePath,
				EnforcementMode: enforcementMode,
			})
		}
	}
	// Build provider registry for route classification
	registry := integrations.NewRegistry()
	registry.Register(github.NewClassifier())

	// Build integration matcher for broker (shared between forward proxy and gateway)
	var matcher *broker.IntegrationMatcher
	if cfg.Broker.Enabled {
		var defs []broker.IntegrationDef
		for _, ic := range cfg.Broker.Integrations {
			if !ic.Enabled {
				continue
			}
			// Default provider to integration name if not explicitly set
			provider := ic.Provider
			if provider == "" {
				provider = ic.Name
			}
			defs = append(defs, broker.IntegrationDef{
				Name:     ic.Name,
				Hosts:    ic.Hosts,
				Provider: provider,
			})
		}
		matcher = broker.NewMatcher(defs)
	}

	proxyServer := proxy.NewProxyServer(cfg, matcher, egressCallback)
	go func() {
		if err := proxyServer.ListenAndServe(cfg.ProxyListen); err != nil {
			log.Errorf("Forward proxy error: %v", err)
		}
	}()

	// Broker gateway (dedicated internal listener)
	var brokerApp *fiber.App
	if cfg.Broker.Enabled {

		// Build credential broker based on config
		var credBroker broker.CredentialBroker

		// Check if any integration uses Pro as credential source
		usePro := false
		for _, ic := range cfg.Broker.Integrations {
			if ic.Enabled && ic.CredentialSource == "pro" {
				usePro = true
				break
			}
		}

		if usePro && cfg.Broker.ProURL != "" {
			credBroker = broker.NewProBroker(broker.ProBrokerConfig{
				ProURL:    cfg.Broker.ProURL,
				APIKeyEnv: cfg.Broker.APIKeyEnv,
			})
			log.Infof("Broker credential source: Pro (%s)", cfg.Broker.ProURL)
		} else {
			devSources := make(map[string]broker.DevStaticConfig)
			for _, ic := range cfg.Broker.Integrations {
				if !ic.Enabled {
					continue
				}
				if ic.CredentialSource == "dev_static" && ic.StaticTokenEnv != "" {
					devSources[ic.Name] = broker.DevStaticConfig{
						TokenEnv:   ic.StaticTokenEnv,
						HeaderName: ic.HeaderName,
						Prefix:     ic.TokenPrefix,
					}
				}
			}
			if len(devSources) > 0 {
				credBroker = broker.NewDevStaticBroker(devSources)
				log.Infof("Broker credential source: dev_static")
			} else {
				credBroker = broker.NewNoopBroker()
				log.Infof("Broker credential source: noop (no credentials configured)")
			}
		}

		// Broker telemetry callback
		var brokerCallback broker.TelemetryCallback
		if collector != nil {
			brokerCallback = func(actionType, target, decision, rulePath, enforcementMode string, params map[string]any) {
				collector.Record(telemetry.TelemetryEvent{
					ActionType:      actionType,
					ActionTarget:    target,
					Decision:        decision,
					RulePath:        rulePath,
					EnforcementMode: enforcementMode,
					ActionParams:    params,
				})
			}
		}

		gw := broker.NewGateway(broker.GatewayConfig{
			Matcher:  matcher,
			Registry: registry,
			Broker:   credBroker,
			Mode:     cfg.Broker.Mode,
			FailBeh:  cfg.Broker.FailBehavior,
			OnEvent:  brokerCallback,
			AgentID:  cfg.Telemetry.AgentID,
		})

		// Separate Fiber app for broker -- no auth middleware (internal-only, network segmentation is the trust boundary)
		brokerApp = fiber.New(fiber.Config{
			AppName:      "Parachute-Broker",
			ServerHeader: "Parachute-Broker",
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second,
		})
		brokerApp.Use(recover.New())
		brokerApp.Get("/health", func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "ok", "service": "broker"})
		})
		brokerApp.All("/broker/:integration/*", gw.Handler())

		go func() {
			if err := brokerApp.Listen(cfg.Broker.Listen); err != nil {
				log.Errorf("Broker gateway error: %v", err)
			}
		}()
		log.Infof("Broker gateway enabled on %s (mode=%s, fail_behavior=%s)", cfg.Broker.Listen, cfg.Broker.Mode, cfg.Broker.FailBehavior)
		log.Infof("Managed integrations: %v", matcher.Integrations())
	}

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

	if collector != nil {
		if err := collector.Close(); err != nil {
			log.Errorf("Telemetry shutdown error: %v", err)
		}
	}

	if brokerApp != nil {
		if err := brokerApp.ShutdownWithContext(shutdownCtx); err != nil {
			log.Errorf("Broker gateway shutdown error: %v", err)
		}
	}

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Errorf("Shutdown error: %v", err)
	}

	log.Info("Goodbye!")
}

// loadWebhooks loads webhook configurations from config
func loadWebhooks(cfg *config.Config) []approval.WebhookConfig {
	webhooks := make([]approval.WebhookConfig, 0, len(cfg.Webhooks))
	for _, wh := range cfg.Webhooks {
		webhooks = append(webhooks, approval.WebhookConfig{
			URL:     wh.URL,
			Method:  wh.Method,
			Headers: wh.Headers,
		})
	}
	return webhooks
}

// Config type conversion helpers for MCP
func toMCPServerPolicy(p config.MCPServerPolicy) mcp.ServerPolicy {
	return mcp.ServerPolicy{
		BlockTools:      p.BlockTools,
		RequireApproval: p.RequireApproval,
		AllowTools:      p.AllowTools,
		BlockResources:  p.BlockResources,
	}
}

func toMCPServerPolicies(policies map[string]config.MCPServerPolicy) map[string]mcp.ServerPolicy {
	if policies == nil {
		return nil
	}
	result := make(map[string]mcp.ServerPolicy, len(policies))
	for k, v := range policies {
		result[k] = toMCPServerPolicy(v)
	}
	return result
}

func toMCPUpstreams(upstreams []config.MCPUpstreamConfig) []mcp.ServerConfig {
	result := make([]mcp.ServerConfig, 0, len(upstreams))
	for _, u := range upstreams {
		transport := u.Transport
		if transport == "" {
			transport = "http"
		}
		result = append(result, mcp.ServerConfig{
			Name:      u.Name,
			URL:       u.URL,
			Transport: transport,
			Command:   u.Command,
		})
	}
	return result
}

// parseDuration parses a Go duration string with a fallback default.
func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
