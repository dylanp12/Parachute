package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      any             `json:"id"`
}

type jsonrpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	Result  any    `json:"result"`
	ID      any    `json:"id"`
}

func main() {
	listen := ":3001"
	if v := os.Getenv("LISTEN"); v != "" {
		listen = v
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req jsonrpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]string{
					{"type": "text", "text": fmt.Sprintf("Mock result for %s", req.Method)},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	fmt.Printf("Mock MCP server listening on %s\n", listen)
	http.ListenAndServe(listen, nil)
}
