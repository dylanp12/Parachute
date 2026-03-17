package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	mux := http.NewServeMux()

	// Health endpoint — no auth required
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		logRequest(r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// All other endpoints require auth
	mux.HandleFunc("/user", requireAuth(handleUser))
	mux.HandleFunc("/repos/", requireAuth(handleRepos))

	addr := ":" + port
	fmt.Printf("Mock GitHub API listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// logRequest prints a structured log line for each incoming request.
func logRequest(r *http.Request) {
	hasAuth := r.Header.Get("Authorization") != ""
	log.Printf("[%s] %s %s auth=%v", time.Now().Format(time.RFC3339), r.Method, r.URL.Path, hasAuth)
}

// requireAuth wraps a handler and returns 401 if no Authorization header is present.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logRequest(r)
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "Bad credentials",
			})
			return
		}
		next(w, r)
	}
}

// handleUser responds to GET /user with a fake user object.
func handleUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"login": "demo-bot",
		"id":    12345,
		"type":  "User",
	})
}

// handleRepos routes /repos/{owner}/{repo}/* to the appropriate sub-handler.
func handleRepos(w http.ResponseWriter, r *http.Request) {
	// Parse path segments: /repos/{owner}/{repo}[/{resource}]
	path := strings.TrimPrefix(r.URL.Path, "/repos/")
	segments := strings.Split(path, "/")

	if len(segments) < 2 {
		http.NotFound(w, r)
		return
	}

	owner := segments[0]
	repo := segments[1]
	fullName := owner + "/" + repo

	// Determine sub-resource
	var resource string
	if len(segments) >= 3 {
		resource = segments[2]
	}

	w.Header().Set("Content-Type", "application/json")

	switch resource {
	case "":
		// GET /repos/{owner}/{repo}
		json.NewEncoder(w).Encode(map[string]any{
			"full_name":   fullName,
			"private":     false,
			"description": "Demo repository",
		})

	case "issues":
		// GET /repos/{owner}/{repo}/issues
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"number": 1,
				"title":  "Add credential broker support",
				"state":  "open",
				"user":   map[string]any{"login": "demo-bot"},
				"labels": []map[string]any{
					{"name": "enhancement"},
				},
			},
			{
				"number": 2,
				"title":  "Fix token rotation edge case",
				"state":  "open",
				"user":   map[string]any{"login": "demo-bot"},
				"labels": []map[string]any{
					{"name": "bug"},
				},
			},
		})

	case "pulls":
		// GET /repos/{owner}/{repo}/pulls
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"number": 10,
				"title":  "Implement broker gateway",
				"state":  "open",
				"user":   map[string]any{"login": "demo-bot"},
				"head":   map[string]any{"ref": "feature/broker"},
				"base":   map[string]any{"ref": "main"},
			},
		})

	default:
		http.NotFound(w, r)
	}
}
