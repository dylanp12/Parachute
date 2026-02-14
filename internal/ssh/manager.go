package ssh

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Manager handles SSH connection pooling and target management
type Manager struct {
	mu          sync.RWMutex
	targets     map[string]*Target
	connections map[string]*pooledConnection
	defaults    ManagerConfig
}

// ManagerConfig holds default settings for the SSH manager
type ManagerConfig struct {
	// DefaultTimeout for command execution (default: 30s)
	DefaultTimeout time.Duration

	// ConnectTimeout for establishing SSH connections (default: 10s)
	ConnectTimeout time.Duration

	// KeepAliveInterval for SSH connections (default: 30s)
	KeepAliveInterval time.Duration

	// MaxIdleTime before closing an idle connection (default: 5m)
	MaxIdleTime time.Duration
}

type pooledConnection struct {
	client       *ssh.Client
	target       *Target
	connectedAt  time.Time
	lastUsedAt   time.Time
	sessionCount int
	mu           sync.Mutex
	// For chained connections, we keep track of intermediate connections
	intermediates []*ssh.Client
}

// NewManager creates a new SSH connection manager
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.DefaultTimeout == 0 {
		cfg.DefaultTimeout = 30 * time.Second
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.KeepAliveInterval == 0 {
		cfg.KeepAliveInterval = 30 * time.Second
	}
	if cfg.MaxIdleTime == 0 {
		cfg.MaxIdleTime = 5 * time.Minute
	}

	m := &Manager{
		targets:     make(map[string]*Target),
		connections: make(map[string]*pooledConnection),
		defaults:    cfg,
	}

	// Start background cleanup of idle connections
	go m.cleanupLoop()

	return m
}

// AddTarget registers a new SSH target
func (m *Manager) AddTarget(t *Target) error {
	if err := t.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.targets[t.Name] = t
	return nil
}

// RemoveTarget unregisters an SSH target and closes any active connection
func (m *Manager) RemoveTarget(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.targets[name]; !ok {
		return fmt.Errorf("target %q not found", name)
	}

	// Close any active connection
	if pc, ok := m.connections[name]; ok {
		m.closePooledConnection(pc)
		delete(m.connections, name)
	}

	delete(m.targets, name)
	return nil
}

// GetTarget retrieves a target by name
func (m *Manager) GetTarget(name string) (*Target, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.targets[name]
	return t, ok
}

// ListTargets returns all registered targets
func (m *Manager) ListTargets() []*Target {
	m.mu.RLock()
	defer m.mu.RUnlock()

	targets := make([]*Target, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, t)
	}
	return targets
}

// ListConnections returns connection info for all targets
func (m *Manager) ListConnections() []*ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]*ConnectionInfo, 0, len(m.targets))
	for _, t := range m.targets {
		info := &ConnectionInfo{Target: t}
		if pc, ok := m.connections[t.Name]; ok {
			info.Connected = true
			info.ConnectedAt = pc.connectedAt
			info.LastUsedAt = pc.lastUsedAt
			info.SessionCount = pc.sessionCount
		}
		infos = append(infos, info)
	}
	return infos
}

// ResolveChain resolves the full SSH hop chain for a target
// Returns the ordered list of targets from first hop to final destination
func (m *Manager) ResolveChain(targetName string) ([]*Target, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var chain []*Target
	visited := make(map[string]bool)
	current := targetName

	// Walk backwards through ProxyJump references to build the chain
	var hops []string
	for current != "" {
		if visited[current] {
			return nil, fmt.Errorf("circular SSH chain detected at target %q", current)
		}
		visited[current] = true

		target, ok := m.targets[current]
		if !ok {
			return nil, fmt.Errorf("target %q not found in chain", current)
		}
		if !target.Enabled {
			return nil, fmt.Errorf("target %q is disabled", current)
		}

		hops = append(hops, current)
		current = target.ProxyJump
	}

	// Reverse to get the chain in connection order (first hop first)
	for i := len(hops) - 1; i >= 0; i-- {
		chain = append(chain, m.targets[hops[i]])
	}

	return chain, nil
}

// GetConnection returns an existing connection or creates a new one
// For chained targets, it establishes connections through intermediate hops
func (m *Manager) GetConnection(targetName string) (*ssh.Client, error) {
	m.mu.RLock()
	if pc, ok := m.connections[targetName]; ok {
		pc.mu.Lock()
		pc.lastUsedAt = time.Now()
		pc.mu.Unlock()
		m.mu.RUnlock()
		return pc.client, nil
	}
	m.mu.RUnlock()

	// Resolve the chain
	chain, err := m.ResolveChain(targetName)
	if err != nil {
		return nil, err
	}

	// Build the connection chain
	var intermediates []*ssh.Client
	var currentClient *ssh.Client

	for i, target := range chain {
		config, err := m.buildSSHConfig(target)
		if err != nil {
			// Clean up any intermediate connections on failure
			for _, c := range intermediates {
				c.Close()
			}
			return nil, fmt.Errorf("failed to build SSH config for %q: %w", target.Name, err)
		}

		var conn net.Conn
		if currentClient == nil {
			// First hop: direct TCP connection
			conn, err = net.DialTimeout("tcp", target.Addr(), m.defaults.ConnectTimeout)
			if err != nil {
				for _, c := range intermediates {
					c.Close()
				}
				return nil, fmt.Errorf("failed to connect to %q (%s): %w", target.Name, target.Addr(), err)
			}
		} else {
			// Subsequent hops: tunnel through the previous connection
			conn, err = currentClient.Dial("tcp", target.Addr())
			if err != nil {
				for _, c := range intermediates {
					c.Close()
				}
				return nil, fmt.Errorf("failed to tunnel to %q through chain: %w", target.Name, err)
			}
		}

		// Perform SSH handshake over the connection
		nconn, chans, reqs, err := ssh.NewClientConn(conn, target.Addr(), config)
		if err != nil {
			conn.Close()
			for _, c := range intermediates {
				c.Close()
			}
			return nil, fmt.Errorf("SSH handshake failed for %q: %w", target.Name, err)
		}

		client := ssh.NewClient(nconn, chans, reqs)

		// Keep intermediate clients for cleanup
		if i < len(chain)-1 {
			intermediates = append(intermediates, client)
		}
		currentClient = client
	}

	// Pool the final connection
	m.mu.Lock()
	m.connections[targetName] = &pooledConnection{
		client:        currentClient,
		target:        chain[len(chain)-1],
		connectedAt:   time.Now(),
		lastUsedAt:    time.Now(),
		intermediates: intermediates,
	}
	m.mu.Unlock()

	return currentClient, nil
}

// Disconnect closes the connection to a target
func (m *Manager) Disconnect(targetName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pc, ok := m.connections[targetName]
	if !ok {
		return nil // Already disconnected
	}

	m.closePooledConnection(pc)
	delete(m.connections, targetName)
	return nil
}

// DisconnectAll closes all SSH connections
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, pc := range m.connections {
		m.closePooledConnection(pc)
		delete(m.connections, name)
	}
}

// TestConnection verifies SSH connectivity to a target
func (m *Manager) TestConnection(targetName string) error {
	client, err := m.GetConnection(targetName)
	if err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		// Connection is stale, remove it and try again
		m.Disconnect(targetName)
		client, err = m.GetConnection(targetName)
		if err != nil {
			return fmt.Errorf("reconnection failed: %w", err)
		}
		session, err = client.NewSession()
		if err != nil {
			return fmt.Errorf("session creation failed after reconnect: %w", err)
		}
	}
	defer session.Close()

	// Run a simple command to verify
	output, err := session.CombinedOutput("echo parachute_ssh_ok")
	if err != nil {
		return fmt.Errorf("test command failed: %w", err)
	}

	if len(output) == 0 {
		return fmt.Errorf("test command returned empty output")
	}

	return nil
}

// buildSSHConfig creates an ssh.ClientConfig for a target
func (m *Manager) buildSSHConfig(target *Target) (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            target.User,
		Timeout:         m.defaults.ConnectTimeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Add host key verification
	}

	switch target.AuthMethod {
	case "key_file":
		key, err := os.ReadFile(target.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %q: %w", target.KeyFile, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key file %q: %w", target.KeyFile, err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

	case "key":
		keyData := os.Getenv(target.KeyEnv)
		if keyData == "" {
			return nil, fmt.Errorf("environment variable %q is empty", target.KeyEnv)
		}
		signer, err := ssh.ParsePrivateKey([]byte(keyData))
		if err != nil {
			return nil, fmt.Errorf("failed to parse key from env %q: %w", target.KeyEnv, err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

	case "password_env":
		password := os.Getenv(target.PasswordEnv)
		if password == "" {
			return nil, fmt.Errorf("environment variable %q is empty", target.PasswordEnv)
		}
		config.Auth = []ssh.AuthMethod{ssh.Password(password)}

	case "agent":
		// SSH agent forwarding - connect to SSH_AUTH_SOCK
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			return nil, fmt.Errorf("SSH_AUTH_SOCK not set for agent auth")
		}
		conn, err := net.Dial("unix", socket)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
		}
		agentClient := NewAgentClient(conn)
		config.Auth = []ssh.AuthMethod{ssh.PublicKeysCallback(agentClient.Signers)}

	default:
		return nil, fmt.Errorf("unsupported auth method: %q", target.AuthMethod)
	}

	return config, nil
}

func (m *Manager) closePooledConnection(pc *pooledConnection) {
	if pc.client != nil {
		pc.client.Close()
	}
	// Close intermediates in reverse order
	for i := len(pc.intermediates) - 1; i >= 0; i-- {
		pc.intermediates[i].Close()
	}
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for name, pc := range m.connections {
			pc.mu.Lock()
			idle := now.Sub(pc.lastUsedAt)
			pc.mu.Unlock()

			if idle > m.defaults.MaxIdleTime {
				m.closePooledConnection(pc)
				delete(m.connections, name)
			}
		}
		m.mu.Unlock()
	}
}
