package sdr

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// Sign computes the canonical JSON of the SDR, computes its SHA-256 hash,
// signs it with the given Ed25519 private key, and populates the Chain.RecordHash
// and Signing fields.
//
// The signing input is the canonical JSON bytes (which exclude the Signing block).
// The RecordHash is the SHA-256 of those same canonical bytes.
func Sign(record *SDR, privateKey ed25519.PrivateKey, keyID string) error {
	canonical, err := CanonicalJSON(record)
	if err != nil {
		return fmt.Errorf("canonical encoding: %w", err)
	}

	// Compute record hash
	hash := sha256.Sum256(canonical)
	record.Chain.RecordHash = hex.EncodeToString(hash[:])

	// Sign the canonical bytes
	signature := ed25519.Sign(privateKey, canonical)
	record.Signing = SigningInfo{
		KeyID:       keyID,
		Algorithm:   "Ed25519",
		Signature:   base64.RawURLEncoding.EncodeToString(signature),
		SigningTime: time.Now().UTC(),
	}

	return nil
}

// Verify checks the SDR signature against the provided public key.
// It recomputes the canonical JSON, verifies the record hash, and
// verifies the Ed25519 signature.
//
// Returns nil if the signature is valid, or an error describing the failure.
func Verify(record *SDR, publicKey ed25519.PublicKey) error {
	canonical, err := CanonicalJSON(record)
	if err != nil {
		return fmt.Errorf("canonical encoding: %w", err)
	}

	// Verify record hash
	hash := sha256.Sum256(canonical)
	expectedHash := hex.EncodeToString(hash[:])
	if record.Chain.RecordHash != expectedHash {
		return fmt.Errorf("record hash mismatch for SDR %s: expected %s, got %s",
			record.SDRID, expectedHash, record.Chain.RecordHash)
	}

	// Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(record.Signing.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature for SDR %s: %w", record.SDRID, err)
	}

	// Verify Ed25519 signature
	if !ed25519.Verify(publicKey, canonical, sigBytes) {
		return fmt.Errorf("signature verification failed for SDR %s", record.SDRID)
	}

	return nil
}

// ComputeRecordHash computes the SHA-256 hash of the canonical JSON encoding.
func ComputeRecordHash(record *SDR) (string, error) {
	canonical, err := CanonicalJSON(record)
	if err != nil {
		return "", fmt.Errorf("canonical encoding: %w", err)
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}
