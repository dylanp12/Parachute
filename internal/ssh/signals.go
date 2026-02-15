package ssh

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/parachute-security/parachute/internal/audit"
)

// SSH signal constants
const SignalKill = ssh.SIGKILL

// SSH-specific audit event types
const (
	EventSSHExecute       audit.EventType = "ssh_execute"
	EventSSHComplete      audit.EventType = "ssh_complete"
	EventSSHError         audit.EventType = "ssh_error"
	EventSSHTimeout       audit.EventType = "ssh_timeout"
	EventSSHBlock         audit.EventType = "ssh_block"
	EventSSHPending       audit.EventType = "ssh_pending"
	EventSSHApprove       audit.EventType = "ssh_approve"
	EventSSHDeny          audit.EventType = "ssh_deny"
	EventSSHConnect       audit.EventType = "ssh_connect"
	EventSSHHostKeyFail   audit.EventType = "ssh_host_key_fail"
	EventSSHPIIDetected   audit.EventType = "ssh_pii_detected"
	EventSSHEgressBlocked audit.EventType = "ssh_egress_blocked"
	EventSSHSessionLimit  audit.EventType = "ssh_session_limit"
	EventSSHStaleConn     audit.EventType = "ssh_stale_connection"
)

// extractExitCode extracts the exit code from an SSH error
func extractExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*ssh.ExitError); ok {
		return exitErr.ExitStatus()
	}

	// Try to parse from error message
	var code int
	if n, _ := fmt.Sscanf(err.Error(), "Process exited with status %d", &code); n == 1 {
		return code
	}

	return -1
}
