package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/dylanp12/parachute/internal/audit"
)

func main() {
	auditLog := flag.String("audit-log", "", "Path to audit log file (JSON lines with hash chain)")
	flag.Parse()

	if *auditLog == "" {
		fmt.Fprintln(os.Stderr, "Usage: parachute-verify --audit-log <path>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Verifies the integrity of a Parachute audit log hash chain.")
		fmt.Fprintln(os.Stderr, "Each log entry contains a cryptographic hash of the previous entry,")
		fmt.Fprintln(os.Stderr, "creating a tamper-evident chain. This tool detects any modifications.")
		os.Exit(1)
	}

	file, err := os.Open(*auditLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var events []audit.HashChainEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large entries
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event audit.HashChainEvent
		if err := json.Unmarshal(line, &event); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing line %d: %v\n", lineNum, err)
			os.Exit(1)
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Verifying %d audit log entries...\n", len(events))

	if err := audit.VerifyChain(events); err != nil {
		fmt.Fprintf(os.Stderr, "INTEGRITY VIOLATION: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("OK: All %d entries verified. Chain integrity is intact.\n", len(events))
}
