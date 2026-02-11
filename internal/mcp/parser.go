package mcp

import (
	"encoding/json"
	"fmt"
)

// ParseMessage parses a raw JSON-RPC message from bytes
func ParseMessage(data []byte) (*JSONRPCRequest, error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}

	if req.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported JSON-RPC version: %s", req.JSONRPC)
	}

	if req.Method == "" {
		return nil, fmt.Errorf("missing method field")
	}

	return &req, nil
}

// ParseToolCall extracts tool call params from a tools/call request
func ParseToolCall(req *JSONRPCRequest) (*ToolCallParams, error) {
	if req.Method != MethodToolsCall {
		return nil, fmt.Errorf("not a tools/call request: %s", req.Method)
	}

	if req.Params == nil {
		return nil, fmt.Errorf("missing params in tools/call request")
	}

	tc := &ToolCallParams{
		Arguments: make(map[string]any),
	}

	if name, ok := req.Params["name"].(string); ok {
		tc.Name = name
	} else {
		return nil, fmt.Errorf("missing or invalid tool name in params")
	}

	if args, ok := req.Params["arguments"].(map[string]any); ok {
		tc.Arguments = args
	}

	return tc, nil
}

// ParseResourceRead extracts resource read params from a resources/read request
func ParseResourceRead(req *JSONRPCRequest) (*ResourceReadParams, error) {
	if req.Method != MethodResourcesRead {
		return nil, fmt.Errorf("not a resources/read request: %s", req.Method)
	}

	if req.Params == nil {
		return nil, fmt.Errorf("missing params in resources/read request")
	}

	rr := &ResourceReadParams{}
	if uri, ok := req.Params["uri"].(string); ok {
		rr.URI = uri
	} else {
		return nil, fmt.Errorf("missing or invalid URI in params")
	}

	return rr, nil
}

// IsToolCall returns true if the request is a tools/call method
func IsToolCall(req *JSONRPCRequest) bool {
	return req.Method == MethodToolsCall
}

// IsResourceRead returns true if the request is a resources/read method
func IsResourceRead(req *JSONRPCRequest) bool {
	return req.Method == MethodResourcesRead
}

// IsSensitiveMethod returns true for methods that may need policy evaluation
func IsSensitiveMethod(method string) bool {
	switch method {
	case MethodToolsCall, MethodResourcesRead:
		return true
	default:
		return false
	}
}

// IsNotification returns true if the request is a JSON-RPC notification (no ID)
func IsNotification(req *JSONRPCRequest) bool {
	return req.ID == nil
}
