package mcp

// JSON-RPC 2.0 types for MCP (Model Context Protocol)

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// MCP method constants
const (
	MethodInitialize   = "initialize"
	MethodToolsList    = "tools/list"
	MethodToolsCall    = "tools/call"
	MethodResourcesRead = "resources/read"
	MethodResourcesList = "resources/list"
	MethodPromptsGet   = "prompts/get"
	MethodPromptsList  = "prompts/list"
)

// Standard JSON-RPC error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
	ErrCodeServerError    = -32000 // Used for policy blocks and timeouts
)

// ToolCallParams represents the params of a tools/call request
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ResourceReadParams represents the params of a resources/read request
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// NewErrorResponse creates a JSON-RPC error response
func NewErrorResponse(id any, code int, message string, data any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// NewResultResponse creates a JSON-RPC success response
func NewResultResponse(id any, result any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
