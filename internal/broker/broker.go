package broker

import (
	"context"
	"fmt"
	"os"
)

// NoopBroker always allows passthrough without credential injection.
// Used when broker is disabled or no credential source is configured.
type NoopBroker struct{}

func NewNoopBroker() *NoopBroker { return &NoopBroker{} }

func (b *NoopBroker) Resolve(_ context.Context, req *BrokerRequest) (*BrokerResult, error) {
	return &BrokerResult{
		Decision:    DecisionAllow,
		Integration: req.Integration,
		RouteClass:  req.RouteClass,
		Reason:      "broker disabled or no credential source",
	}, nil
}

// DevStaticBroker resolves credentials from environment variables.
// This is for development and local testing only -- not for production.
type DevStaticBroker struct {
	sources map[string]staticSource // integration name → source config
}

type staticSource struct {
	envVar     string
	headerName string
	prefix     string
}

// DevStaticConfig holds config for a single static credential source.
type DevStaticConfig struct {
	TokenEnv   string // env var name containing the token
	HeaderName string // header to set (default: "Authorization")
	Prefix     string // prefix before token (default: "Bearer ")
	NoPrefix   bool   // set true to use no prefix (empty Prefix is treated as default)
}

// NewDevStaticBroker creates a broker for dev/local use that reads tokens from env vars.
func NewDevStaticBroker(sources map[string]DevStaticConfig) *DevStaticBroker {
	m := make(map[string]staticSource, len(sources))
	for name, cfg := range sources {
		headerName := cfg.HeaderName
		if headerName == "" {
			headerName = "Authorization"
		}
		prefix := cfg.Prefix
		if prefix == "" && !cfg.NoPrefix {
			prefix = "Bearer "
		}
		m[name] = staticSource{
			envVar:     cfg.TokenEnv,
			headerName: headerName,
			prefix:     prefix,
		}
	}
	return &DevStaticBroker{sources: m}
}

func (b *DevStaticBroker) Resolve(_ context.Context, req *BrokerRequest) (*BrokerResult, error) {
	src, ok := b.sources[req.Integration]
	if !ok {
		return &BrokerResult{
			Decision:    DecisionUnavailable,
			Integration: req.Integration,
			RouteClass:  req.RouteClass,
			Reason:      fmt.Sprintf("no static credential configured for %s", req.Integration),
		}, nil
	}

	token := os.Getenv(src.envVar)
	if token == "" {
		return &BrokerResult{
			Decision:    DecisionUnavailable,
			Integration: req.Integration,
			RouteClass:  req.RouteClass,
			Reason:      fmt.Sprintf("env var %s is empty", src.envVar),
		}, nil
	}

	return &BrokerResult{
		Decision:    DecisionCredentialInjected,
		Integration: req.Integration,
		RouteClass:  req.RouteClass,
		Credential: &Credential{
			HeaderName:  src.headerName,
			HeaderValue: src.prefix + token,
		},
	}, nil
}
