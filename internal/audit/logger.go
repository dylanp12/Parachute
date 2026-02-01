package audit

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType defines the type of audit event
type EventType string

const (
	EventIngressAllow   EventType = "ingress_allow"
	EventIngressDeny    EventType = "ingress_deny"
	EventCommandBlock   EventType = "command_block"
	EventCommandPending EventType = "command_pending"
	EventCommandApprove EventType = "command_approve"
	EventCommandDeny    EventType = "command_deny"
	EventCommandExpire  EventType = "command_expire"
	EventEgressAllow    EventType = "egress_allow"
	EventEgressDeny     EventType = "egress_deny"
	EventPIIScrub       EventType = "pii_scrub"
	EventRateLimit      EventType = "rate_limit"
	EventAuthFail       EventType = "auth_fail"
)

// Event represents a structured audit log event
type Event struct {
	Timestamp     time.Time         `json:"timestamp"`
	EventType     EventType         `json:"event_type"`
	CorrelationID string            `json:"correlation_id"`
	ClientIP      string            `json:"client_ip,omitempty"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	Command       string            `json:"command,omitempty"`
	CommandID     string            `json:"command_id,omitempty"`
	ToolName      string            `json:"tool_name,omitempty"`
	Action        string            `json:"action,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	Domain        string            `json:"domain,omitempty"`
	Pattern       string            `json:"pattern,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
	Duration      time.Duration     `json:"duration_ns,omitempty"`
}

// Logger provides structured audit logging
type Logger struct {
	mu      sync.Mutex
	encoder *json.Encoder
	output  io.Writer
}

// NewLogger creates a new audit logger that writes to the given output
func NewLogger(output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		encoder: json.NewEncoder(output),
		output:  output,
	}
}

// NewFileLogger creates an audit logger that writes to a file
func NewFileLogger(path string) (*Logger, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return NewLogger(file), nil
}

// Log writes an audit event
func (l *Logger) Log(event *Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.CorrelationID == "" {
		event.CorrelationID = GenerateCorrelationID()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.encoder.Encode(event); err != nil {
		log.Printf("[AUDIT:ERROR] Failed to write audit log: %v", err)
	}
}

// LogIngress logs an ingress event (allow/deny)
func (l *Logger) LogIngress(allowed bool, correlationID, clientIP, method, path, reason string) {
	eventType := EventIngressAllow
	if !allowed {
		eventType = EventIngressDeny
	}

	l.Log(&Event{
		EventType:     eventType,
		CorrelationID: correlationID,
		ClientIP:      clientIP,
		Method:        method,
		Path:          path,
		Reason:        reason,
	})
}

// LogCommand logs a command interception event
func (l *Logger) LogCommand(eventType EventType, correlationID, commandID, command, toolName, reason string) {
	l.Log(&Event{
		EventType:     eventType,
		CorrelationID: correlationID,
		CommandID:     commandID,
		Command:       command,
		ToolName:      toolName,
		Reason:        reason,
	})
}

// LogEgress logs an egress event (allow/deny)
func (l *Logger) LogEgress(allowed bool, correlationID, domain, reason string) {
	eventType := EventEgressAllow
	if !allowed {
		eventType = EventEgressDeny
	}

	l.Log(&Event{
		EventType:     eventType,
		CorrelationID: correlationID,
		Domain:        domain,
		Reason:        reason,
	})
}

// LogPII logs a PII scrubbing event
func (l *Logger) LogPII(correlationID, pattern string) {
	l.Log(&Event{
		EventType:     EventPIIScrub,
		CorrelationID: correlationID,
		Pattern:       pattern,
		Reason:        "PII detected and blocked",
	})
}

// LogAuth logs an authentication failure
func (l *Logger) LogAuth(correlationID, clientIP, reason string) {
	l.Log(&Event{
		EventType:     EventAuthFail,
		CorrelationID: correlationID,
		ClientIP:      clientIP,
		Reason:        reason,
	})
}

// LogRateLimit logs a rate limit event
func (l *Logger) LogRateLimit(correlationID, clientIP string) {
	l.Log(&Event{
		EventType:     EventRateLimit,
		CorrelationID: correlationID,
		ClientIP:      clientIP,
		Reason:        "rate limit exceeded",
	})
}

// GenerateCorrelationID creates a new correlation ID
func GenerateCorrelationID() string {
	return uuid.New().String()[:8]
}

// DefaultLogger is the global audit logger
var DefaultLogger = NewLogger(os.Stdout)

// SetDefaultLogger sets the default audit logger
func SetDefaultLogger(l *Logger) {
	DefaultLogger = l
}

// Quick access functions using default logger

// Log logs an event to the default logger
func Log(event *Event) {
	DefaultLogger.Log(event)
}

// LogIngressAllow logs an allowed ingress request
func LogIngressAllow(correlationID, clientIP, method, path string) {
	DefaultLogger.LogIngress(true, correlationID, clientIP, method, path, "")
}

// LogIngressDeny logs a denied ingress request
func LogIngressDeny(correlationID, clientIP, method, path, reason string) {
	DefaultLogger.LogIngress(false, correlationID, clientIP, method, path, reason)
}

// LogCommandBlock logs a blocked command
func LogCommandBlock(correlationID, commandID, command, toolName, reason string) {
	DefaultLogger.LogCommand(EventCommandBlock, correlationID, commandID, command, toolName, reason)
}

// LogCommandPending logs a command awaiting approval
func LogCommandPending(correlationID, commandID, command, toolName, reason string) {
	DefaultLogger.LogCommand(EventCommandPending, correlationID, commandID, command, toolName, reason)
}

// LogCommandApprove logs an approved command
func LogCommandApprove(correlationID, commandID, command, toolName string) {
	DefaultLogger.LogCommand(EventCommandApprove, correlationID, commandID, command, toolName, "")
}

// LogCommandDenyAction logs a denied command
func LogCommandDenyAction(correlationID, commandID, command, toolName string) {
	DefaultLogger.LogCommand(EventCommandDeny, correlationID, commandID, command, toolName, "")
}

// LogCommandExpire logs an expired command
func LogCommandExpire(correlationID, commandID, command, toolName string) {
	DefaultLogger.LogCommand(EventCommandExpire, correlationID, commandID, command, toolName, "timeout")
}

// LogEgressAllow logs an allowed egress request
func LogEgressAllow(correlationID, domain string) {
	DefaultLogger.LogEgress(true, correlationID, domain, "")
}

// LogEgressDeny logs a denied egress request
func LogEgressDeny(correlationID, domain, reason string) {
	DefaultLogger.LogEgress(false, correlationID, domain, reason)
}

// LogPIIDetected logs a PII detection event
func LogPIIDetected(correlationID, pattern string) {
	DefaultLogger.LogPII(correlationID, pattern)
}

// LogAuthFailure logs an authentication failure
func LogAuthFailure(correlationID, clientIP, reason string) {
	DefaultLogger.LogAuth(correlationID, clientIP, reason)
}

// LogRateLimited logs a rate limit event
func LogRateLimited(correlationID, clientIP string) {
	DefaultLogger.LogRateLimit(correlationID, clientIP)
}
