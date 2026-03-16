package mcp

import "testing"

func TestSSEBrokerPublishSubscribe(t *testing.T) {
	b := NewSSEBroker(10)
	ch := b.Subscribe("corr-1")

	b.Publish("corr-1", "result", map[string]string{"status": "ok"})

	select {
	case event := <-ch:
		if event.Type != "result" {
			t.Errorf("unexpected type: %s", event.Type)
		}
		if event.ID != 1 {
			t.Errorf("unexpected id: %d", event.ID)
		}
	default:
		t.Fatal("expected event on channel")
	}

	b.Unsubscribe("corr-1")
}

func TestSSEBrokerEventsSince(t *testing.T) {
	b := NewSSEBroker(10)
	b.Publish("x", "a", nil)
	b.Publish("x", "b", nil)
	b.Publish("x", "c", nil)

	events := b.EventsSince(1)
	if len(events) != 2 {
		t.Errorf("expected 2 events after id 1, got %d", len(events))
	}
}

func TestSSEBrokerBufferLimit(t *testing.T) {
	b := NewSSEBroker(3)
	for i := 0; i < 5; i++ {
		b.Publish("x", "test", i)
	}

	events := b.EventsSince(0)
	if len(events) != 3 {
		t.Errorf("expected 3 events (buffer size), got %d", len(events))
	}
}

func TestSSEBrokerDefaultBufferSize(t *testing.T) {
	b := NewSSEBroker(0)
	if b.bufSize != 100 {
		t.Errorf("expected default buffer size 100, got %d", b.bufSize)
	}

	b2 := NewSSEBroker(-5)
	if b2.bufSize != 100 {
		t.Errorf("expected default buffer size 100, got %d", b2.bufSize)
	}
}

func TestSSEBrokerUnsubscribeUnknown(t *testing.T) {
	b := NewSSEBroker(10)
	// Should not panic
	b.Unsubscribe("nonexistent")
}

func TestSSEBrokerPublishNoSubscriber(t *testing.T) {
	b := NewSSEBroker(10)
	// Should not panic; event goes to buffer only
	b.Publish("nobody", "test", "data")

	events := b.EventsSince(0)
	if len(events) != 1 {
		t.Errorf("expected 1 buffered event, got %d", len(events))
	}
}

func TestSSEBrokerMultipleCorrelations(t *testing.T) {
	b := NewSSEBroker(10)
	ch1 := b.Subscribe("corr-1")
	ch2 := b.Subscribe("corr-2")

	b.Publish("corr-1", "result", "for-1")
	b.Publish("corr-2", "result", "for-2")

	select {
	case event := <-ch1:
		if event.Data != "for-1" {
			t.Errorf("corr-1 got wrong data: %v", event.Data)
		}
	default:
		t.Fatal("expected event on corr-1 channel")
	}

	select {
	case event := <-ch2:
		if event.Data != "for-2" {
			t.Errorf("corr-2 got wrong data: %v", event.Data)
		}
	default:
		t.Fatal("expected event on corr-2 channel")
	}

	b.Unsubscribe("corr-1")
	b.Unsubscribe("corr-2")
}

func TestSSEBrokerEventsSinceEmpty(t *testing.T) {
	b := NewSSEBroker(10)
	events := b.EventsSince(0)
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestSSEBrokerIDsMonotonic(t *testing.T) {
	b := NewSSEBroker(10)
	b.Publish("x", "a", nil)
	b.Publish("x", "b", nil)
	b.Publish("x", "c", nil)

	events := b.EventsSince(0)
	for i := 1; i < len(events); i++ {
		if events[i].ID <= events[i-1].ID {
			t.Errorf("event IDs not monotonically increasing: %d <= %d", events[i].ID, events[i-1].ID)
		}
	}
}
