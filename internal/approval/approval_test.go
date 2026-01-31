package approval

import (
	"context"
	"testing"
	"time"
)

func TestQueueAddAndList(t *testing.T) {
	q := NewQueue(1 * time.Minute)
	pc := q.Add("rm -rf temp", "bash", "dangerous command", nil)

	if pc.ID == "" {
		t.Error("Expected non-empty ID")
	}

	pending := q.List()
	if len(pending) != 1 {
		t.Errorf("Expected 1 pending, got %d", len(pending))
	}
}

func TestQueueApprove(t *testing.T) {
	q := NewQueue(1 * time.Minute)
	pc := q.Add("sudo apt update", "bash", "requires approval", nil)

	done := make(chan Decision)
	go func() {
		decision := q.Wait(context.Background(), pc.ID)
		done <- decision
	}()

	time.Sleep(10 * time.Millisecond)

	if !q.Approve(pc.ID) {
		t.Error("Approve returned false")
	}

	select {
	case decision := <-done:
		if decision != DecisionApproved {
			t.Errorf("Expected DecisionApproved, got %v", decision)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for decision")
	}
}

func TestQueueDeny(t *testing.T) {
	q := NewQueue(1 * time.Minute)
	pc := q.Add("curl evil.com", "bash", "risky", nil)

	done := make(chan Decision)
	go func() {
		decision := q.Wait(context.Background(), pc.ID)
		done <- decision
	}()

	time.Sleep(10 * time.Millisecond)

	if !q.Deny(pc.ID) {
		t.Error("Deny returned false")
	}

	select {
	case decision := <-done:
		if decision != DecisionDenied {
			t.Errorf("Expected DecisionDenied, got %v", decision)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for decision")
	}
}

func TestQueueTimeout(t *testing.T) {
	q := NewQueue(50 * time.Millisecond)
	pc := q.Add("test", "bash", "test", nil)

	start := time.Now()
	decision := q.Wait(context.Background(), pc.ID)
	elapsed := time.Since(start)

	if decision != DecisionExpired {
		t.Errorf("Expected DecisionExpired, got %v", decision)
	}

	if elapsed > 200*time.Millisecond {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

func TestQueueGet(t *testing.T) {
	q := NewQueue(1 * time.Minute)
	pc := q.Add("test cmd", "bash", "reason", nil)

	got, exists := q.Get(pc.ID)
	if !exists {
		t.Error("Expected to find pending command")
	}
	if got.Command != "test cmd" {
		t.Errorf("Expected 'test cmd', got '%s'", got.Command)
	}

	_, exists = q.Get("nonexistent")
	if exists {
		t.Error("Expected not to find non-existent command")
	}
}
