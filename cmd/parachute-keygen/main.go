package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	privPath := flag.String("private", "sidecar.key", "Path to write the private key (PEM)")
	pubPath := flag.String("public", "sidecar.pub", "Path to write the public key (PEM)")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv,
	})
	if err := os.WriteFile(*privPath, privPEM, 0600); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	})
	if err := os.WriteFile(*pubPath, pubPEM, 0644); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}

	keyID := "sidecar/" + hex.EncodeToString(pub[:8])
	fmt.Printf("Keypair generated:\n")
	fmt.Printf("  Private key: %s (keep secret, configure in parachute.yaml -> telemetry.signing.key_path)\n", *privPath)
	fmt.Printf("  Public key:  %s (copy to Pro's trusted_keys_dir)\n", *pubPath)
	fmt.Printf("  Key ID:      %s\n", keyID)
}
