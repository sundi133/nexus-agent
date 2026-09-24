package telemetry

import (
	"testing"

	"github.com/sundi133/nexus-agent/internal/api"
)

func ev(t string) api.Event { return api.Event{Type: t} }

func TestBufferBoundedAndFIFO(t *testing.T) {
	b := NewBuffer(3)
	b.Add(ev("1"), ev("2"), ev("3"), ev("4"))
	if b.Len() != 3 || b.Dropped() != 1 {
		t.Fatalf("len=%d dropped=%d", b.Len(), b.Dropped())
	}
	got := b.Take(2)
	if got[0].Type != "2" || got[1].Type != "3" {
		t.Fatalf("take: %+v", got)
	}
	b.Requeue(got)
	all := b.Take(10)
	if len(all) != 3 || all[0].Type != "2" || all[2].Type != "4" {
		t.Fatalf("requeue order: %+v", all)
	}
}
