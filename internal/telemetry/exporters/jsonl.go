package exporters

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/dylanp12/parachute/pkg/sdr"
)

// JSONLExporter writes SDR records as one-per-line JSON to a file.
// It also serves as the write-ahead log for the HTTP batch exporter.
type JSONLExporter struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
}

// NewJSONLExporter creates a JSONL exporter writing to the given path.
// Creates parent directories if needed. Appends to existing file.
func NewJSONLExporter(path string) (*JSONLExporter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &JSONLExporter{
		file:   f,
		writer: bufio.NewWriterSize(f, 65536),
	}, nil
}

// Export writes a batch of SDR records as JSONL.
func (e *JSONLExporter) Export(_ context.Context, records []sdr.SDR) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range records {
		data, err := json.Marshal(&records[i])
		if err != nil {
			continue // skip malformed records
		}
		e.writer.Write(data)
		e.writer.WriteByte('\n')
	}

	return e.writer.Flush()
}

// Close flushes and closes the underlying file.
func (e *JSONLExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writer.Flush()
	return e.file.Close()
}
