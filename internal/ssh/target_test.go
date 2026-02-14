package ssh

import (
	"testing"
)

func TestTargetAddr(t *testing.T) {
	tests := []struct {
		name     string
		target   Target
		expected string
	}{
		{
			name:     "default port",
			target:   Target{Host: "example.com"},
			expected: "example.com:22",
		},
		{
			name:     "custom port",
			target:   Target{Host: "example.com", Port: 2222},
			expected: "example.com:2222",
		},
		{
			name:     "ip address",
			target:   Target{Host: "10.0.0.1", Port: 22},
			expected: "10.0.0.1:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.target.Addr()
			if got != tt.expected {
				t.Errorf("Addr() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestTargetValidate(t *testing.T) {
	tests := []struct {
		name    string
		target  Target
		wantErr bool
	}{
		{
			name: "valid key_file target",
			target: Target{
				Name:       "dev-server",
				Host:       "dev.example.com",
				User:       "deploy",
				Port:       22,
				AuthMethod: "key_file",
				KeyFile:    "/path/to/key",
				Enabled:    true,
			},
			wantErr: false,
		},
		{
			name: "valid key target",
			target: Target{
				Name:       "staging",
				Host:       "staging.example.com",
				User:       "deploy",
				AuthMethod: "key",
				KeyEnv:     "SSH_KEY",
				Enabled:    true,
			},
			wantErr: false,
		},
		{
			name: "valid password_env target",
			target: Target{
				Name:        "test",
				Host:        "test.example.com",
				User:        "admin",
				AuthMethod:  "password_env",
				PasswordEnv: "SSH_PASSWORD",
				Enabled:     true,
			},
			wantErr: false,
		},
		{
			name: "valid agent target",
			target: Target{
				Name:       "agent-auth",
				Host:       "server.example.com",
				User:       "deploy",
				AuthMethod: "agent",
				Enabled:    true,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			target: Target{
				Host:       "example.com",
				User:       "deploy",
				AuthMethod: "key_file",
				KeyFile:    "/path/to/key",
			},
			wantErr: true,
		},
		{
			name: "missing host",
			target: Target{
				Name:       "test",
				User:       "deploy",
				AuthMethod: "key_file",
				KeyFile:    "/path/to/key",
			},
			wantErr: true,
		},
		{
			name: "missing user",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				AuthMethod: "key_file",
				KeyFile:    "/path/to/key",
			},
			wantErr: true,
		},
		{
			name: "missing auth_method",
			target: Target{
				Name: "test",
				Host: "example.com",
				User: "deploy",
			},
			wantErr: true,
		},
		{
			name: "key_file missing file path",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				User:       "deploy",
				AuthMethod: "key_file",
			},
			wantErr: true,
		},
		{
			name: "key missing env var",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				User:       "deploy",
				AuthMethod: "key",
			},
			wantErr: true,
		},
		{
			name: "password_env missing env var",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				User:       "deploy",
				AuthMethod: "password_env",
			},
			wantErr: true,
		},
		{
			name: "unknown auth_method",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				User:       "deploy",
				AuthMethod: "magic",
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				User:       "deploy",
				Port:       -1,
				AuthMethod: "agent",
			},
			wantErr: true,
		},
		{
			name: "port too high",
			target: Target{
				Name:       "test",
				Host:       "example.com",
				User:       "deploy",
				Port:       70000,
				AuthMethod: "agent",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.target.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestManagerAddAndListTargets(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	target := &Target{
		Name:       "test-server",
		Host:       "10.0.0.1",
		Port:       22,
		User:       "testuser",
		AuthMethod: "key_file",
		KeyFile:    "/tmp/test_key",
		Enabled:    true,
	}

	if err := mgr.AddTarget(target); err != nil {
		t.Fatalf("AddTarget() error = %v", err)
	}

	targets := mgr.ListTargets()
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Name != "test-server" {
		t.Errorf("expected name 'test-server', got %q", targets[0].Name)
	}

	// Get by name
	got, ok := mgr.GetTarget("test-server")
	if !ok {
		t.Fatal("GetTarget() returned false")
	}
	if got.Host != "10.0.0.1" {
		t.Errorf("expected host '10.0.0.1', got %q", got.Host)
	}

	// Not found
	_, ok = mgr.GetTarget("nonexistent")
	if ok {
		t.Error("GetTarget() should return false for nonexistent target")
	}
}

func TestManagerRemoveTarget(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	target := &Target{
		Name:       "removable",
		Host:       "10.0.0.2",
		User:       "test",
		AuthMethod: "agent",
		Enabled:    true,
	}

	mgr.AddTarget(target)

	if err := mgr.RemoveTarget("removable"); err != nil {
		t.Fatalf("RemoveTarget() error = %v", err)
	}

	_, ok := mgr.GetTarget("removable")
	if ok {
		t.Error("target should be removed")
	}

	if err := mgr.RemoveTarget("nonexistent"); err == nil {
		t.Error("RemoveTarget() should return error for nonexistent target")
	}
}

func TestManagerResolveChain(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	// Set up a chain: local -> bastion -> app-server
	mgr.AddTarget(&Target{
		Name:       "bastion",
		Host:       "bastion.example.com",
		User:       "ops",
		AuthMethod: "agent",
		Enabled:    true,
	})
	mgr.AddTarget(&Target{
		Name:       "app-server",
		Host:       "10.0.1.5",
		User:       "deploy",
		AuthMethod: "key_file",
		KeyFile:    "/tmp/key",
		ProxyJump:  "bastion",
		Enabled:    true,
	})

	chain, err := mgr.ResolveChain("app-server")
	if err != nil {
		t.Fatalf("ResolveChain() error = %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("expected chain length 2, got %d", len(chain))
	}
	if chain[0].Name != "bastion" {
		t.Errorf("first hop should be 'bastion', got %q", chain[0].Name)
	}
	if chain[1].Name != "app-server" {
		t.Errorf("second hop should be 'app-server', got %q", chain[1].Name)
	}
}

func TestManagerResolveChainDirect(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	mgr.AddTarget(&Target{
		Name:       "direct",
		Host:       "direct.example.com",
		User:       "admin",
		AuthMethod: "agent",
		Enabled:    true,
	})

	chain, err := mgr.ResolveChain("direct")
	if err != nil {
		t.Fatalf("ResolveChain() error = %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("expected chain length 1, got %d", len(chain))
	}
	if chain[0].Name != "direct" {
		t.Errorf("expected 'direct', got %q", chain[0].Name)
	}
}

func TestManagerResolveChainCircular(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	mgr.AddTarget(&Target{
		Name:       "a",
		Host:       "a.example.com",
		User:       "user",
		AuthMethod: "agent",
		ProxyJump:  "b",
		Enabled:    true,
	})
	mgr.AddTarget(&Target{
		Name:       "b",
		Host:       "b.example.com",
		User:       "user",
		AuthMethod: "agent",
		ProxyJump:  "a",
		Enabled:    true,
	})

	_, err := mgr.ResolveChain("a")
	if err == nil {
		t.Error("ResolveChain() should detect circular chain")
	}
}

func TestManagerResolveChainDisabled(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	mgr.AddTarget(&Target{
		Name:       "disabled-target",
		Host:       "example.com",
		User:       "user",
		AuthMethod: "agent",
		Enabled:    false,
	})

	_, err := mgr.ResolveChain("disabled-target")
	if err == nil {
		t.Error("ResolveChain() should reject disabled targets")
	}
}

func TestManagerResolveChainMissing(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	_, err := mgr.ResolveChain("nonexistent")
	if err == nil {
		t.Error("ResolveChain() should return error for nonexistent target")
	}
}

func TestManagerResolveThreeHopChain(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	mgr.AddTarget(&Target{
		Name:       "hop1",
		Host:       "hop1.example.com",
		User:       "user",
		AuthMethod: "agent",
		Enabled:    true,
	})
	mgr.AddTarget(&Target{
		Name:       "hop2",
		Host:       "hop2.example.com",
		User:       "user",
		AuthMethod: "agent",
		ProxyJump:  "hop1",
		Enabled:    true,
	})
	mgr.AddTarget(&Target{
		Name:       "final",
		Host:       "final.example.com",
		User:       "user",
		AuthMethod: "agent",
		ProxyJump:  "hop2",
		Enabled:    true,
	})

	chain, err := mgr.ResolveChain("final")
	if err != nil {
		t.Fatalf("ResolveChain() error = %v", err)
	}

	if len(chain) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(chain))
	}
	if chain[0].Name != "hop1" {
		t.Errorf("hop 0 = %q, want hop1", chain[0].Name)
	}
	if chain[1].Name != "hop2" {
		t.Errorf("hop 1 = %q, want hop2", chain[1].Name)
	}
	if chain[2].Name != "final" {
		t.Errorf("hop 2 = %q, want final", chain[2].Name)
	}
}

func TestListConnections(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	mgr.AddTarget(&Target{
		Name:       "server-a",
		Host:       "a.example.com",
		User:       "user",
		AuthMethod: "agent",
		Enabled:    true,
	})
	mgr.AddTarget(&Target{
		Name:       "server-b",
		Host:       "b.example.com",
		User:       "user",
		AuthMethod: "agent",
		Enabled:    true,
	})

	conns := mgr.ListConnections()
	if len(conns) != 2 {
		t.Fatalf("expected 2 connection infos, got %d", len(conns))
	}

	// None should be connected since we haven't established any
	for _, c := range conns {
		if c.Connected {
			t.Errorf("target %q should not be connected", c.Target.Name)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "'simple'"},
		{"with space", "'with space'"},
		{"it's", "'it'\\''s'"},
		{"", "''"},
	}

	for _, tt := range tests {
		got := shellQuote(tt.input)
		if got != tt.expected {
			t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTruncateCmd(t *testing.T) {
	short := "ls -la"
	if got := truncateCmd(short); got != short {
		t.Errorf("truncateCmd short = %q, want %q", got, short)
	}

	long := ""
	for i := 0; i < 150; i++ {
		long += "a"
	}
	got := truncateCmd(long)
	if len(got) != 103 { // 100 + "..."
		t.Errorf("truncateCmd long length = %d, want 103", len(got))
	}
}
