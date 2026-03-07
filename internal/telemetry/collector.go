package telemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/dylanp12/parachute/pkg/sdr"
)

// Exporter writes SDR records to a destination.
type Exporter interface {
	Export(ctx context.Context, records []sdr.SDR) error
	Close() error
}

// CollectorConfig configures the telemetry collector.
type CollectorConfig struct {
	AgentID        string
	TenantID       string
	SidecarVersion string
	QueueSize      int // default 10000
	SigningKey     ed25519.PrivateKey
	KeyID          string
}

// CollectorMetrics exposes collector counters.
type CollectorMetrics struct {
	EventsRecorded int64
	EventsDropped  int64
}

// Collector aggregates events from egress and MCP, converts to SDR, and dispatches to exporters.
type Collector struct {
	cfg        CollectorConfig
	signingKey ed25519.PrivateKey
	keyID      string
	sessionID  string
	chainState *ChainState
	queue      chan *sdr.SDR
	exporters  []Exporter
	done       chan struct{}

	eventsRecorded atomic.Int64
	eventsDropped  atomic.Int64
}

// NewCollector creates a new telemetry collector.
func NewCollector(cfg CollectorConfig, chainState *ChainState, exporters []Exporter) *Collector {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	if cfg.AgentID == "" {
		cfg.AgentID = uuid.New().String()
	}
	if chainState.ChainID == "" {
		chainState.ChainID = cfg.AgentID
	}

	return &Collector{
		cfg:        cfg,
		signingKey: cfg.SigningKey,
		keyID:      cfg.KeyID,
		sessionID:  uuid.New().String(),
		chainState: chainState,
		queue:      make(chan *sdr.SDR, cfg.QueueSize),
		exporters:  exporters,
		done:       make(chan struct{}),
	}
}

// Record converts a TelemetryEvent to an SDR and queues it for export.
// Non-blocking. Drops the event if the queue is full.
func (c *Collector) Record(event TelemetryEvent) {
	c.RecordWithParent(event, "")
}

// RecordWithParent records an event linked to a parent span.
func (c *Collector) RecordWithParent(event TelemetryEvent, parentSpanID string) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	spanID := event.SpanID
	if spanID == "" {
		spanID = uuid.New().String()[:8]
	}
	if parentSpanID == "" {
		parentSpanID = event.ParentSpanID
	}

	prevHash, chainID := c.chainState.GetChainInfo()

	record := &sdr.SDR{
		SDRVersion: sdr.SDRVersion,
		SDRID:      uuid.New(),
		TenantID:   c.cfg.TenantID,
		AgentID:    c.cfg.AgentID,
		OccurredAt: event.Timestamp,
		Action: sdr.ActionInfo{
			Type:   event.ActionType,
			Target: event.ActionTarget,
			Params: event.ActionParams,
		},
		Policy: sdr.PolicyInfo{
			Decision: event.Decision,
			RulePath: event.RulePath,
		},
		Chain: sdr.ChainInfo{
			PrevHash: prevHash,
			ChainID:  chainID,
		},
		Signing: sdr.SigningInfo{
			KeyID:       "unsigned",
			Algorithm:   "none",
			SigningTime: event.Timestamp,
		},
		Runtime: sdr.RuntimeInfo{
			SidecarVersion: c.cfg.SidecarVersion,
		},
		Telemetry: sdr.TelemetryContext{
			SessionID:    c.sessionID,
			SpanID:       spanID,
			ParentSpanID: parentSpanID,
		},
		Enforcement: sdr.EnforcementInfo{
			Mode: event.EnforcementMode,
		},
	}

	if event.Approval != nil {
		record.Approval = &sdr.ApprovalInfo{
			ID:             event.Approval.ID,
			ApproverID:     event.Approval.ApproverID,
			ApproverType:   event.Approval.ApproverType,
			ApprovalSource: event.Approval.ApprovalSource,
			Justification:  event.Approval.Justification,
			DecisionTime:   event.Approval.DecisionTime,
		}
	}

	if c.signingKey != nil {
		// Sign the record (also sets Chain.RecordHash)
		if err := sdr.Sign(record, c.signingKey, c.keyID); err != nil {
			// Fall back to unsigned with manual hash
			record.Signing = sdr.SigningInfo{
				KeyID:       "unsigned",
				Algorithm:   "none",
				SigningTime: event.Timestamp,
			}
			canonical, err := sdr.CanonicalJSON(record)
			if err == nil {
				hash := sha256.Sum256(canonical)
				record.Chain.RecordHash = hex.EncodeToString(hash[:])
			}
		}
	} else {
		// No signing key: unsigned with manual hash
		canonical, err := sdr.CanonicalJSON(record)
		if err == nil {
			hash := sha256.Sum256(canonical)
			record.Chain.RecordHash = hex.EncodeToString(hash[:])
		}
	}

	// Advance chain state
	if record.Chain.RecordHash != "" {
		c.chainState.Advance(record.Chain.RecordHash)
	}

	// Non-blocking queue
	select {
	case c.queue <- record:
		c.eventsRecorded.Add(1)
	default:
		c.eventsDropped.Add(1)
	}
}

// Start begins the export loop.
func (c *Collector) Start(ctx context.Context) {
	go c.exportLoop(ctx)
}

func (c *Collector) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var batch []sdr.SDR

	for {
		select {
		case record := <-c.queue:
			batch = append(batch, *record)
			if len(batch) >= 50 {
				c.flush(ctx, batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.flush(ctx, batch)
				batch = nil
			}
		case <-ctx.Done():
			// Drain remaining
			close(c.queue)
			for record := range c.queue {
				batch = append(batch, *record)
			}
			if len(batch) > 0 {
				c.flush(context.Background(), batch)
			}
			close(c.done)
			return
		}
	}
}

func (c *Collector) flush(ctx context.Context, batch []sdr.SDR) {
	for _, exp := range c.exporters {
		_ = exp.Export(ctx, batch)
	}
}

// Close waits for the export loop to finish and closes all exporters.
func (c *Collector) Close() error {
	<-c.done
	c.chainState.Sync()
	for _, exp := range c.exporters {
		exp.Close()
	}
	return nil
}

// Metrics returns current collector counters.
func (c *Collector) Metrics() CollectorMetrics {
	return CollectorMetrics{
		EventsRecorded: c.eventsRecorded.Load(),
		EventsDropped:  c.eventsDropped.Load(),
	}
}
