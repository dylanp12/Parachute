package exporters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/dylanp12/parachute/pkg/sdr"
)

// HTTPBatchConfig configures the HTTP batch exporter.
type HTTPBatchConfig struct {
	ProURL        string
	APIKey        string
	SpoolPath     string        // JSONL file to read from
	OffsetPath    string        // tracks upload position
	BatchSize     int           // default 50
	FlushInterval time.Duration // default 10s
}

// HTTPBatchExporter reads SDRs from the JSONL spool and uploads to Pro.
type HTTPBatchExporter struct {
	cfg    HTTPBatchConfig
	client *http.Client
	done   chan struct{}
}

// NewHTTPBatchExporter creates a new HTTP batch exporter.
func NewHTTPBatchExporter(cfg HTTPBatchConfig) (*HTTPBatchExporter, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}

	return &HTTPBatchExporter{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		done:   make(chan struct{}),
	}, nil
}

// Start begins the spool-reading upload loop.
func (e *HTTPBatchExporter) Start(ctx context.Context) {
	go e.uploadLoop(ctx)
}

// Export is a no-op for the HTTP exporter (it reads from the spool file instead).
func (e *HTTPBatchExporter) Export(_ context.Context, _ []sdr.SDR) error {
	return nil
}

// Close waits for the upload loop to stop.
func (e *HTTPBatchExporter) Close() error {
	<-e.done
	return nil
}

func (e *HTTPBatchExporter) uploadLoop(ctx context.Context) {
	defer close(e.done)

	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.uploadPending()
		case <-ctx.Done():
			e.uploadPending() // final flush
			return
		}
	}
}

func (e *HTTPBatchExporter) uploadPending() {
	offset := e.loadOffset()

	f, err := os.Open(e.cfg.SpoolPath)
	if err != nil {
		return
	}
	defer f.Close()

	if offset > 0 {
		f.Seek(offset, io.SeekStart)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line limit

	var batch []sdr.SDR
	var bytesRead int64

	for scanner.Scan() {
		line := scanner.Bytes()
		bytesRead += int64(len(line)) + 1 // +1 for newline

		var record sdr.SDR
		if err := json.Unmarshal(line, &record); err != nil {
			continue
		}
		batch = append(batch, record)

		if len(batch) >= e.cfg.BatchSize {
			if err := e.sendBatch(batch); err != nil {
				return // retry next tick
			}
			offset += bytesRead
			e.saveOffset(offset)
			batch = nil
			bytesRead = 0
		}
	}

	if len(batch) > 0 {
		if err := e.sendBatch(batch); err != nil {
			return
		}
		offset += bytesRead
		e.saveOffset(offset)
	}
}

func (e *HTTPBatchExporter) sendBatch(records []sdr.SDR) error {
	batch := sdr.Batch{
		BatchID: uuid.New().String(),
		Records: records,
	}

	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", e.cfg.ProURL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if e.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.APIKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ingest returned %d", resp.StatusCode)
	}

	return nil
}

func (e *HTTPBatchExporter) loadOffset() int64 {
	data, err := os.ReadFile(e.cfg.OffsetPath)
	if err != nil {
		return 0
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return offset
}

func (e *HTTPBatchExporter) saveOffset(offset int64) {
	os.WriteFile(e.cfg.OffsetPath, []byte(strconv.FormatInt(offset, 10)), 0644)
}
