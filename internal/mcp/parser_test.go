package mcp

import (
	"testing"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		method  string
	}{
		{
			name:   "valid tools/call",
			input:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_bash","arguments":{"command":"ls -la"}}}`,
			method: "tools/call",
		},
		{
			name:   "valid tools/list",
			input:  `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			method: "tools/list",
		},
		{
			name:   "valid resources/read",
			input:  `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`,
			method: "resources/read",
		},
		{
			name:   "valid initialize",
			input:  `{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}`,
			method: "initialize",
		},
		{
			name:    "invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:    "wrong version",
			input:   `{"jsonrpc":"1.0","id":1,"method":"test"}`,
			wantErr: true,
		},
		{
			name:    "missing method",
			input:   `{"jsonrpc":"2.0","id":1}`,
			wantErr: true,
		},
		{
			name:   "string ID",
			input:  `{"jsonrpc":"2.0","id":"abc-123","method":"tools/list"}`,
			method: "tools/list",
		},
		{
			name:   "notification (null ID)",
			input:  `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"abc"}}`,
			method: "notifications/cancelled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseMessage([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Method != tt.method {
				t.Errorf("method = %q, want %q", req.Method, tt.method)
			}
		})
	}
}

func TestParseToolCall(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantArgs map[string]any
		wantErr  bool
	}{
		{
			name:     "basic tool call",
			input:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_bash","arguments":{"command":"ls -la"}}}`,
			wantName: "execute_bash",
			wantArgs: map[string]any{"command": "ls -la"},
		},
		{
			name:     "tool call without arguments",
			input:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status"}}`,
			wantName: "get_status",
		},
		{
			name:     "tool call with complex arguments",
			input:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"SELECT * FROM users","limit":10}}}`,
			wantName: "query_db",
		},
		{
			name:    "not a tools/call",
			input:   `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			wantErr: true,
		},
		{
			name:    "missing tool name",
			input:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseMessage([]byte(tt.input))
			if err != nil {
				t.Fatalf("parse message: %v", err)
			}

			tc, err := ParseToolCall(req)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.Name != tt.wantName {
				t.Errorf("name = %q, want %q", tc.Name, tt.wantName)
			}
		})
	}
}

func TestParseResourceRead(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantURI string
		wantErr bool
	}{
		{
			name:    "valid resource read",
			input:   `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`,
			wantURI: "file:///etc/passwd",
		},
		{
			name:    "not a resources/read",
			input:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}`,
			wantErr: true,
		},
		{
			name:    "missing URI",
			input:   `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseMessage([]byte(tt.input))
			if err != nil {
				t.Fatalf("parse message: %v", err)
			}

			rr, err := ParseResourceRead(req)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rr.URI != tt.wantURI {
				t.Errorf("URI = %q, want %q", rr.URI, tt.wantURI)
			}
		})
	}
}

func TestIsSensitiveMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"tools/call", true},
		{"resources/read", true},
		{"tools/list", false},
		{"initialize", false},
		{"prompts/get", false},
	}

	for _, tt := range tests {
		if got := IsSensitiveMethod(tt.method); got != tt.want {
			t.Errorf("IsSensitiveMethod(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestIsNotification(t *testing.T) {
	req1, _ := ParseMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if IsNotification(req1) {
		t.Error("expected non-notification")
	}

	req2, _ := ParseMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`))
	if !IsNotification(req2) {
		t.Error("expected notification")
	}
}
