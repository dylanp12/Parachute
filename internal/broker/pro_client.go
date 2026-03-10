package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// ProBroker resolves credentials by calling the Pro control plane API.
// This is the production CredentialBroker implementation.
type ProBroker struct {
	proURL string
	apiKey string
	client *http.Client

	// Local response cache (keyed by "integration:route_class")
	mu    sync.RWMutex
	cache map[string]*cachedResponse
}

type cachedResponse struct {
	result    *BrokerResult
	expiresAt time.Time
}

// ProBrokerConfig holds configuration for the ProBroker client.
type ProBrokerConfig struct {
	ProURL    string // e.g., "https://pro.example.com"
	APIKeyEnv string // env var containing the API key
}

// NewProBroker creates a production credential broker that calls Pro.
func NewProBroker(cfg ProBrokerConfig) *ProBroker {
	apiKey := os.Getenv(cfg.APIKeyEnv)

	return &ProBroker{
		proURL: cfg.ProURL,
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Direct dial -- bypass HTTP_PROXY/HTTPS_PROXY to prevent self-loops
				Proxy: nil,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		cache: make(map[string]*cachedResponse),
	}
}

// Resolve calls the Pro API to resolve a credential for the given request.
// Results are cached locally for their TTL.
func (pb *ProBroker) Resolve(ctx context.Context, req *BrokerRequest) (*BrokerResult, error) {
	// Check cache
	cacheKey := req.Integration + ":" + req.RouteClass
	if result := pb.getCached(cacheKey); result != nil {
		return result, nil
	}

	// Build request body
	body, err := json.Marshal(map[string]string{
		"integration": req.Integration,
		"agent_id":    req.AgentID,
		"method":      req.Method,
		"path":        req.Path,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	// Call Pro API
	url := pb.proURL + "/v1/broker/credential"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+pb.apiKey)

	resp, err := pb.client.Do(httpReq)
	if err != nil {
		// Fail closed: Pro unreachable → credential unavailable
		return &BrokerResult{
			Decision:    DecisionUnavailable,
			Integration: req.Integration,
			RouteClass:  req.RouteClass,
			Reason:      "Pro control plane unreachable: " + err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &BrokerResult{
			Decision:    DecisionUnavailable,
			Integration: req.Integration,
			RouteClass:  req.RouteClass,
			Reason:      fmt.Sprintf("Pro returned status %d", resp.StatusCode),
		}, nil
	}

	// Parse response
	var proResp struct {
		Decision   string `json:"decision"`
		Credential *struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"credential"`
		TTL    int    `json:"ttl"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(respBody, &proResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Map Pro response to BrokerResult
	result := &BrokerResult{
		Integration: req.Integration,
		RouteClass:  req.RouteClass,
		Reason:      proResp.Reason,
	}

	switch proResp.Decision {
	case "allow":
		if proResp.Credential != nil {
			result.Decision = DecisionCredentialInjected
			result.Credential = &Credential{
				HeaderName:  "Authorization",
				HeaderValue: proResp.Credential.Value,
			}
		} else {
			result.Decision = DecisionAllow
		}
	case "deny":
		result.Decision = DecisionDeny
	default:
		result.Decision = DecisionUnavailable
	}

	// Cache the result
	ttl := time.Duration(proResp.TTL) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	pb.setCached(cacheKey, result, ttl)

	return result, nil
}

func (pb *ProBroker) getCached(key string) *BrokerResult {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	entry, ok := pb.cache[key]
	if !ok {
		return nil
	}
	if time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.result
}

func (pb *ProBroker) setCached(key string, result *BrokerResult, ttl time.Duration) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.cache[key] = &cachedResponse{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
}
