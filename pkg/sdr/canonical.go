package sdr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON produces a deterministic JSON encoding of the SDR payload,
// excluding the Signing, Telemetry, and Enforcement blocks. The result is
// used as input for hashing and signing.
//
// Canonicalization rules:
//  1. Object keys are sorted lexicographically at every nesting level.
//  2. No trailing whitespace or newlines.
//  3. Compact format (no indentation).
//  4. Null values are included explicitly (not omitted).
//  5. The "signing" field is excluded from the canonical payload.
//  6. The "telemetry" field is excluded (operational metadata).
//  7. The "enforcement" field is excluded (operational metadata).
//  8. The "record_hash" field within "chain" is excluded (it is derived
//     from the canonical form and cannot include itself).
func CanonicalJSON(record *SDR) ([]byte, error) {
	// Build the payload without the Signing block.
	// We marshal the SDR, remove "signing" and "chain.record_hash",
	// then re-serialize with sorted keys.
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshaling SDR: %w", err)
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("unmarshaling SDR: %w", err)
	}

	// Remove the signing block
	delete(obj, "signing")

	// Remove telemetry (operational metadata, not part of cryptographic payload)
	delete(obj, "telemetry")

	// Remove enforcement (operational metadata, not part of cryptographic payload)
	delete(obj, "enforcement")

	// Remove record_hash from chain (it is derived from canonical form)
	if chain, ok := obj["chain"].(map[string]any); ok {
		delete(chain, "record_hash")
	}

	return marshalSorted(obj)
}

// marshalSorted serializes a value to JSON with object keys sorted
// lexicographically at every nesting level.
func marshalSorted(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf bytes.Buffer
		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			if first {
				first = false
			} else {
				buf.WriteByte(',')
			}
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return nil, fmt.Errorf("marshaling key %q: %w", k, err)
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')

			valBytes, err := marshalSorted(val[k])
			if err != nil {
				return nil, fmt.Errorf("marshaling value for key %q: %w", k, err)
			}
			buf.Write(valBytes)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil

	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			itemBytes, err := marshalSorted(item)
			if err != nil {
				return nil, fmt.Errorf("marshaling array item %d: %w", i, err)
			}
			buf.Write(itemBytes)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil

	default:
		// Primitives: strings, numbers, booleans, null
		return json.Marshal(v)
	}
}
