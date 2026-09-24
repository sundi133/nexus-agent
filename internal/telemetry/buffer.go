package telemetry

import (
	"sync"

	"github.com/sundi133/nexus-agent/internal/api"
)

// Buffer is a bounded FIFO of events awaiting upload. When full, the oldest
// events are dropped: fresh state is more valuable than stale state, and an
// agent must never grow without bound while the cloud is unreachable.
type Buffer struct {
	mu      sync.Mutex
	events  []api.Event
	max     int
	dropped int
}

// NewBuffer creates a buffer holding at most max events.
func NewBuffer(max int) *Buffer { return &Buffer{max: max} }

// Add appends events, evicting the oldest on overflow.
func (b *Buffer) Add(events ...api.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, events...)
	if over := len(b.events) - b.max; over > 0 {
		b.dropped += over
		b.events = append([]api.Event(nil), b.events[over:]...)
	}
}

// Take removes and returns up to n events.
func (b *Buffer) Take(n int) []api.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > len(b.events) {
		n = len(b.events)
	}
	out := append([]api.Event(nil), b.events[:n]...)
	b.events = b.events[n:]
	return out
}

// Requeue puts events back at the front after a failed upload.
func (b *Buffer) Requeue(events []api.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(append([]api.Event(nil), events...), b.events...)
	if over := len(b.events) - b.max; over > 0 {
		b.dropped += over
		b.events = b.events[over:]
	}
}

// Len returns the number of queued events.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// Dropped returns how many events were evicted since creation.
func (b *Buffer) Dropped() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}
