package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// PendingCommand represents a command awaiting approval
type PendingCommand struct {
	ID        string         `json:"id"`
	Command   string         `json:"command"`
	ToolName  string         `json:"tool_name"`
	Args      map[string]any `json:"args"`
	Reason    string         `json:"reason"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Status    string         `json:"status"` // pending, approved, denied, expired
}

// Store provides persistent storage for approval queue
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewStore creates a new SQLite-backed store
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS pending_commands (
		id TEXT PRIMARY KEY,
		command TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		args TEXT NOT NULL,
		reason TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		decided_at DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_status ON pending_commands(status);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON pending_commands(expires_at);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		event_type TEXT NOT NULL,
		command_id TEXT,
		command TEXT,
		action TEXT,
		reason TEXT,
		client_ip TEXT,
		correlation_id TEXT,
		details TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_command_id ON audit_log(command_id);
	CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_log(correlation_id);

	CREATE TABLE IF NOT EXISTS ssh_executions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		correlation_id TEXT NOT NULL,
		target_name TEXT NOT NULL,
		command TEXT NOT NULL,
		exit_code INTEGER NOT NULL,
		stdout TEXT,
		stderr TEXT,
		error TEXT,
		chain TEXT,
		duration_ns INTEGER,
		pii_detected BOOLEAN NOT NULL DEFAULT 0,
		output_truncated BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_ssh_exec_target ON ssh_executions(target_name);
	CREATE INDEX IF NOT EXISTS idx_ssh_exec_correlation ON ssh_executions(correlation_id);
	CREATE INDEX IF NOT EXISTS idx_ssh_exec_created ON ssh_executions(created_at);
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	store := &Store{db: db}

	// Start background cleanup
	go store.cleanupLoop()

	return store, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// Add creates a new pending command
func (s *Store) Add(pc *PendingCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	argsJSON, err := json.Marshal(pc.Args)
	if err != nil {
		return fmt.Errorf("failed to marshal args: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO pending_commands (id, command, tool_name, args, reason, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
	`, pc.ID, pc.Command, pc.ToolName, string(argsJSON), pc.Reason, pc.CreatedAt, pc.ExpiresAt)

	if err != nil {
		return fmt.Errorf("failed to insert pending command: %w", err)
	}

	return nil
}

// Get retrieves a pending command by ID
func (s *Store) Get(id string) (*PendingCommand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, command, tool_name, args, reason, created_at, expires_at, status
		FROM pending_commands
		WHERE id = ?
	`, id)

	pc := &PendingCommand{}
	var argsJSON string

	err := row.Scan(&pc.ID, &pc.Command, &pc.ToolName, &argsJSON, &pc.Reason, &pc.CreatedAt, &pc.ExpiresAt, &pc.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get pending command: %w", err)
	}

	if err := json.Unmarshal([]byte(argsJSON), &pc.Args); err != nil {
		return nil, fmt.Errorf("failed to unmarshal args: %w", err)
	}

	return pc, nil
}

// ListPending returns all pending commands that haven't expired
func (s *Store) ListPending() ([]*PendingCommand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, command, tool_name, args, reason, created_at, expires_at, status
		FROM pending_commands
		WHERE status = 'pending' AND expires_at > ?
		ORDER BY created_at DESC
	`, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to list pending commands: %w", err)
	}
	defer rows.Close()

	var result []*PendingCommand
	for rows.Next() {
		pc := &PendingCommand{}
		var argsJSON string

		err := rows.Scan(&pc.ID, &pc.Command, &pc.ToolName, &argsJSON, &pc.Reason, &pc.CreatedAt, &pc.ExpiresAt, &pc.Status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if err := json.Unmarshal([]byte(argsJSON), &pc.Args); err != nil {
			return nil, fmt.Errorf("failed to unmarshal args: %w", err)
		}

		result = append(result, pc)
	}

	return result, nil
}

// UpdateStatus updates the status of a pending command (approve/deny)
// This is idempotent - calling it multiple times with the same status has no effect
func (s *Store) UpdateStatus(id string, status string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only update if currently pending
	result, err := s.db.Exec(`
		UPDATE pending_commands
		SET status = ?, decided_at = ?
		WHERE id = ? AND status = 'pending'
	`, status, time.Now(), id)

	if err != nil {
		return false, fmt.Errorf("failed to update status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// Approve marks a command as approved
func (s *Store) Approve(id string) (bool, error) {
	return s.UpdateStatus(id, "approved")
}

// Deny marks a command as denied
func (s *Store) Deny(id string) (bool, error) {
	return s.UpdateStatus(id, "denied")
}

// IsExpired checks if a command has expired
func (s *Store) IsExpired(id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT expires_at, status
		FROM pending_commands
		WHERE id = ?
	`, id)

	var expiresAt time.Time
	var status string
	err := row.Scan(&expiresAt, &status)
	if err == sql.ErrNoRows {
		return true, nil // Not found = expired
	}
	if err != nil {
		return false, fmt.Errorf("failed to check expiration: %w", err)
	}

	return status != "pending" || time.Now().After(expiresAt), nil
}

// GetStatus returns the current status of a command
func (s *Store) GetStatus(id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT status, expires_at
		FROM pending_commands
		WHERE id = ?
	`, id)

	var status string
	var expiresAt time.Time
	err := row.Scan(&status, &expiresAt)
	if err == sql.ErrNoRows {
		return "not_found", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get status: %w", err)
	}

	// Check if expired
	if status == "pending" && time.Now().After(expiresAt) {
		// Update to expired
		s.mu.RUnlock()
		s.mu.Lock()
		s.db.Exec(`UPDATE pending_commands SET status = 'expired' WHERE id = ? AND status = 'pending'`, id)
		s.mu.Unlock()
		s.mu.RLock()
		return "expired", nil
	}

	return status, nil
}

// cleanupLoop periodically marks expired commands
func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		s.db.Exec(`
			UPDATE pending_commands
			SET status = 'expired'
			WHERE status = 'pending' AND expires_at < ?
		`, time.Now())
		s.mu.Unlock()
	}
}

// AuditEvent represents a log entry
type AuditEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	CommandID     string    `json:"command_id,omitempty"`
	Command       string    `json:"command,omitempty"`
	Action        string    `json:"action,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	ClientIP      string    `json:"client_ip,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Details       string    `json:"details,omitempty"`
}

// LogEvent records an audit event
func (s *Store) LogEvent(event *AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO audit_log (timestamp, event_type, command_id, command, action, reason, client_ip, correlation_id, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.Timestamp, event.EventType, event.CommandID, event.Command, event.Action, event.Reason, event.ClientIP, event.CorrelationID, event.Details)

	if err != nil {
		return fmt.Errorf("failed to log event: %w", err)
	}

	return nil
}

// SSHExecution represents a stored SSH command execution record
type SSHExecution struct {
	ID              int64     `json:"id"`
	CorrelationID   string    `json:"correlation_id"`
	TargetName      string    `json:"target_name"`
	Command         string    `json:"command"`
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout,omitempty"`
	Stderr          string    `json:"stderr,omitempty"`
	Error           string    `json:"error,omitempty"`
	Chain           string    `json:"chain,omitempty"`
	DurationNs      int64     `json:"duration_ns"`
	PIIDetected     bool      `json:"pii_detected"`
	OutputTruncated bool      `json:"output_truncated"`
	CreatedAt       time.Time `json:"created_at"`
}

// StoreSSHExecution persists an SSH execution result
func (s *Store) StoreSSHExecution(exec *SSHExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO ssh_executions (correlation_id, target_name, command, exit_code, stdout, stderr, error, chain, duration_ns, pii_detected, output_truncated, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, exec.CorrelationID, exec.TargetName, exec.Command, exec.ExitCode,
		exec.Stdout, exec.Stderr, exec.Error, exec.Chain, exec.DurationNs,
		exec.PIIDetected, exec.OutputTruncated, exec.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to store SSH execution: %w", err)
	}
	return nil
}

// ListSSHExecutions retrieves SSH execution history, optionally filtered by target
func (s *Store) ListSSHExecutions(target string, limit int) ([]*SSHExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rows *sql.Rows
	var err error

	if target != "" {
		rows, err = s.db.Query(`
			SELECT id, correlation_id, target_name, command, exit_code, stdout, stderr, error, chain, duration_ns, pii_detected, output_truncated, created_at
			FROM ssh_executions
			WHERE target_name = ?
			ORDER BY created_at DESC
			LIMIT ?
		`, target, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT id, correlation_id, target_name, command, exit_code, stdout, stderr, error, chain, duration_ns, pii_detected, output_truncated, created_at
			FROM ssh_executions
			ORDER BY created_at DESC
			LIMIT ?
		`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH executions: %w", err)
	}
	defer rows.Close()

	var result []*SSHExecution
	for rows.Next() {
		exec := &SSHExecution{}
		var stdout, stderr, execErr, chain sql.NullString

		err := rows.Scan(&exec.ID, &exec.CorrelationID, &exec.TargetName, &exec.Command,
			&exec.ExitCode, &stdout, &stderr, &execErr, &chain,
			&exec.DurationNs, &exec.PIIDetected, &exec.OutputTruncated, &exec.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SSH execution row: %w", err)
		}

		exec.Stdout = stdout.String
		exec.Stderr = stderr.String
		exec.Error = execErr.String
		exec.Chain = chain.String

		result = append(result, exec)
	}

	return result, nil
}

// GetAuditLog retrieves recent audit events
func (s *Store) GetAuditLog(limit int) ([]*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT timestamp, event_type, command_id, command, action, reason, client_ip, correlation_id, details
		FROM audit_log
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}
	defer rows.Close()

	var result []*AuditEvent
	for rows.Next() {
		event := &AuditEvent{}
		var commandID, command, action, reason, clientIP, correlationID, details sql.NullString

		err := rows.Scan(&event.Timestamp, &event.EventType, &commandID, &command, &action, &reason, &clientIP, &correlationID, &details)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		event.CommandID = commandID.String
		event.Command = command.String
		event.Action = action.String
		event.Reason = reason.String
		event.ClientIP = clientIP.String
		event.CorrelationID = correlationID.String
		event.Details = details.String

		result = append(result, event)
	}

	return result, nil
}
