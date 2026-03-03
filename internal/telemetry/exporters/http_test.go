package exporters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/parachute-security/parachute/pkg/sdr"
)

func TestHTTPBatchExporterUploadsFromSpool(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch sdr.Batch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode batch: %v", err)
			w.WriteHeader(400)
			return
		}
		received.Add(int64(len(batch.Records)))
		json.NewEncoder(w).Encode(sdr.IngestResult{Accepted: len(batch.Records)})
	}))
	defer server.Close()

	dir := t.TempDir()
	spoolPath := filepath.Join(dir, "events.jsonl")
	offsetPath := filepath.Join(dir, "offset")

	// Pre-write 3 SDRs to the spool
	f, _ := os.Create(spoolPath)
	for i := 0; i < 3; i++ {
		data, _ := json.Marshal(testSDR("egress", "test.com"))
		f.Write(data)
		f.Write([]byte("\n"))
	}
	f.Close()

	exp, err := NewHTTPBatchExporter(HTTPBatchConfig{
		ProURL:        server.URL,
		SpoolPath:     spoolPath,
		OffsetPath:    offsetPath,
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewHTTPBatchExporter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	exp.Start(ctx)

	// Wait for upload
	time.Sleep(500 * time.Millisecond)
	cancel()
	exp.Close()

	if received.Load() != 3 {
		t.Errorf("expected 3 records uploaded, got %d", received.Load())
	}

	// Verify offset was persisted
	offsetData, _ := os.ReadFile(offsetPath)
	if len(offsetData) == 0 {
		t.Error("offset file should not be empty")
	}
}
