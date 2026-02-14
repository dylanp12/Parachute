package ssh

import (
	"io"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentClient wraps an SSH agent connection for key-based authentication
type AgentClient struct {
	agent agent.Agent
	conn  net.Conn
}

// NewAgentClient creates a new SSH agent client from a connection
func NewAgentClient(conn net.Conn) *AgentClient {
	return &AgentClient{
		agent: agent.NewClient(conn),
		conn:  conn,
	}
}

// Signers returns the signers available from the SSH agent
func (a *AgentClient) Signers() ([]ssh.Signer, error) {
	return a.agent.Signers()
}

// Close closes the agent connection
func (a *AgentClient) Close() error {
	if closer, ok := a.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
