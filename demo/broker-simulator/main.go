package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type scenario struct {
	Number     int
	Method     string
	URL        string
	UseProxy   bool   // if true, send via HTTP_PROXY
	ExpectCode int    // expected HTTP status code
	Label      string // human-readable description
}

func main() {
	brokerURL := getEnv("BROKER_URL", "http://parachute:8081")
	proxyURL := getEnv("PROXY_URL", "http://parachute:8888")

	fmt.Printf("%s%sParachute Credential Broker Demo%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("Broker: %s\n", brokerURL)
	fmt.Printf("Proxy:  %s\n", proxyURL)
	fmt.Println()

	scenarios := []scenario{
		{
			Number:     1,
			Method:     "GET",
			URL:        brokerURL + "/broker/github/user",
			ExpectCode: 200,
			Label:      "Brokered auth: GET /user",
		},
		{
			Number:     2,
			Method:     "GET",
			URL:        brokerURL + "/broker/github/repos/demo-org/demo-repo",
			ExpectCode: 200,
			Label:      "Brokered auth: GET /repos/demo-org/demo-repo",
		},
		{
			Number:     3,
			Method:     "GET",
			URL:        brokerURL + "/broker/github/repos/demo-org/demo-repo/issues",
			ExpectCode: 200,
			Label:      "Brokered auth: GET /repos/.../issues",
		},
		{
			Number:     4,
			Method:     "GET",
			URL:        brokerURL + "/broker/github/repos/demo-org/demo-repo/pulls",
			ExpectCode: 200,
			Label:      "Brokered auth: GET /repos/.../pulls",
		},
		{
			Number:     5,
			Method:     "GET",
			URL:        "http://api.github.com/user",
			UseProxy:   true,
			ExpectCode: 403,
			Label:      "Direct access via proxy: GET api.github.com/user (should be blocked)",
		},
	}

	client := &http.Client{Timeout: 10 * time.Second}

	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Printf("%sFATAL: invalid PROXY_URL: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	proxyClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyParsed),
		},
	}

	// Wait for broker to be healthy
	waitForBroker(client, brokerURL)

	maxLoops := 3
	for loop := 1; loop <= maxLoops; loop++ {
		fmt.Printf("\n%s%s=== Loop %d/%d ===%s\n\n", colorBold, colorCyan, loop, maxLoops, colorReset)

		allPassed := true
		for _, s := range scenarios {
			c := client
			if s.UseProxy {
				c = proxyClient
			}

			passed := runScenario(c, s)
			if !passed {
				allPassed = false
			}
			time.Sleep(1 * time.Second)
		}

		if allPassed {
			fmt.Printf("\n%s%sAll scenarios passed.%s\n", colorBold, colorGreen, colorReset)
		} else {
			fmt.Printf("\n%s%sSome scenarios failed.%s\n", colorBold, colorRed, colorReset)
		}

		if loop < maxLoops {
			fmt.Printf("\nNext loop in 10 seconds...\n")
			time.Sleep(10 * time.Second)
		}
	}

	fmt.Printf("\n%s%sDemo complete. %d loops finished.%s\n", colorBold, colorCyan, maxLoops, colorReset)
}

// waitForBroker polls the broker health endpoint until it responds.
func waitForBroker(client *http.Client, brokerURL string) {
	fmt.Print("Waiting for broker gateway")
	for i := 0; i < 60; i++ {
		resp, err := client.Get(brokerURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 404 {
				// 404 is OK -- means the server is up but /health may not be routed on broker port
				fmt.Printf(" %sready%s\n", colorGreen, colorReset)
				return
			}
		}
		fmt.Print(".")
		time.Sleep(1 * time.Second)
	}
	fmt.Printf("\n%sWARNING: broker may not be ready, continuing anyway%s\n", colorYellow, colorReset)
}

// runScenario executes a single scenario and prints the result.
func runScenario(client *http.Client, s scenario) bool {
	req, err := http.NewRequest(s.Method, s.URL, nil)
	if err != nil {
		printResult(s, 0, false, fmt.Sprintf("request error: %v", err))
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		// For proxy scenarios, connection refused or blocked is expected as a "pass"
		// when we expect 403 -- the proxy blocked the connection at the TCP level
		if s.UseProxy && s.ExpectCode == 403 {
			printResult(s, 0, true, "connection blocked by proxy (expected)")
			return true
		}
		printResult(s, 0, false, fmt.Sprintf("connection error: %v", err))
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	passed := resp.StatusCode == s.ExpectCode

	detail := truncate(string(body), 100)
	printResult(s, resp.StatusCode, passed, detail)
	return passed
}

// printResult displays a formatted scenario result.
func printResult(s scenario, statusCode int, passed bool, detail string) {
	status := fmt.Sprintf("%s PASS %s", colorGreen, colorReset)
	if !passed {
		status = fmt.Sprintf("%s FAIL %s", colorRed, colorReset)
	}

	statusStr := "---"
	if statusCode > 0 {
		statusStr = fmt.Sprintf("%d", statusCode)
	}

	fmt.Printf("  [%d] %s  %s %s  -> %s (expect %d)\n",
		s.Number, status, s.Method, s.Label, statusStr, s.ExpectCode)
	if detail != "" && !passed {
		fmt.Printf("      %s%s%s\n", colorYellow, detail, colorReset)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
