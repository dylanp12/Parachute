package ssh

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/gofiber/fiber/v3/log"
	"github.com/parachute-security/parachute/internal/audit"
)

// DefaultKnownHostsPath is checked when no per-target host key config is set
const DefaultKnownHostsPath = "/etc/parachute/ssh/known_hosts"

// buildHostKeyCallback creates an ssh.HostKeyCallback for a target.
// Priority: HostKeyFingerprint > KnownHostsFile > DefaultKnownHostsPath > reject (fail-closed)
func buildHostKeyCallback(target *Target) (ssh.HostKeyCallback, error) {
	// Option 1: Pinned SHA256 fingerprint
	if target.HostKeyFingerprint != "" {
		return fingerprintCallback(target.Name, target.HostKeyFingerprint)
	}

	// Option 2: Per-target known_hosts file
	if target.KnownHostsFile != "" {
		cb, err := knownhosts.New(target.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts file %q for target %q: %w",
				target.KnownHostsFile, target.Name, err)
		}
		return cb, nil
	}

	// Option 3: Global default known_hosts
	if _, err := os.Stat(DefaultKnownHostsPath); err == nil {
		cb, err := knownhosts.New(DefaultKnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load default known_hosts %q: %w",
				DefaultKnownHostsPath, err)
		}
		return cb, nil
	}

	// Fail-closed: no host key verification configured
	log.Warnf("[SSH] No host key verification configured for target %q - connections will be rejected. "+
		"Set host_key_fingerprint, known_hosts_file, or create %s",
		target.Name, DefaultKnownHostsPath)

	return func(hostname string, remote interface{ String() string }, key ssh.PublicKey) error {
		fp := FingerprintSHA256(key)
		audit.Log(&audit.Event{
			EventType: EventSSHHostKeyFail,
			ToolName:  "ssh_connect",
			Reason:    "no host key verification configured",
			Details: map[string]string{
				"target":      target.Name,
				"hostname":    hostname,
				"fingerprint": fp,
			},
		})
		return fmt.Errorf("host key verification failed for %q: no known_hosts or fingerprint configured (presented key: %s)", target.Name, fp)
	}, nil
}

// fingerprintCallback returns a callback that compares the host key's SHA256 fingerprint
func fingerprintCallback(targetName, expectedFingerprint string) (ssh.HostKeyCallback, error) {
	// Normalize: strip "SHA256:" prefix if present
	expected := strings.TrimPrefix(expectedFingerprint, "SHA256:")
	if expected == "" {
		return nil, fmt.Errorf("empty host key fingerprint for target %q", targetName)
	}

	return func(hostname string, remote interface{ String() string }, key ssh.PublicKey) error {
		actual := computeSHA256Fingerprint(key)
		if actual != expected {
			audit.Log(&audit.Event{
				EventType: EventSSHHostKeyFail,
				ToolName:  "ssh_connect",
				Reason:    "host key fingerprint mismatch",
				Details: map[string]string{
					"target":   targetName,
					"hostname": hostname,
					"expected": "SHA256:" + expected,
					"actual":   "SHA256:" + actual,
				},
			})
			return fmt.Errorf("host key fingerprint mismatch for %q: expected SHA256:%s, got SHA256:%s",
				targetName, expected, actual)
		}
		return nil
	}, nil
}

// computeSHA256Fingerprint returns the base64-encoded SHA256 hash of a public key
func computeSHA256Fingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// FingerprintSHA256 returns the "SHA256:..." fingerprint string for a public key
func FingerprintSHA256(key ssh.PublicKey) string {
	return "SHA256:" + computeSHA256Fingerprint(key)
}
