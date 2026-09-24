package localapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sundi133/nexus-agent/internal/detector"
	"github.com/sundi133/nexus-agent/internal/policy"
)

type stubBackend struct{ last policy.Request }

func (s *stubBackend) Decide(_ context.Context, r policy.Request) policy.Result {
	s.last = r
	if r.Action == "write" {
		return policy.Result{Decision: policy.Deny, Reason: "test"}
	}
	return policy.Result{Decision: policy.Allow, Reason: "test"}
}
func (s *stubBackend) AIAgents() []detector.DetectedAgent { return nil }
func (s *stubBackend) Status() any                        { return map[string]bool{"ok": true} }

func newTestServer(t *testing.T) (*stubBackend, http.Handler) {
	b := &stubBackend{}
	s, err := New("127.0.0.1:0", b, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b, s.Handler()
}

func TestNewRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7443", "10.0.0.5:7443", ":7443"} {
		if _, err := New(addr, &stubBackend{}, slog.Default()); err == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:7443", "[::1]:7443", "localhost:7443"} {
		if _, err := New(addr, &stubBackend{}, slog.Default()); err != nil {
			t.Errorf("%s rejected: %v", addr, err)
		}
	}
}

func TestDecide(t *testing.T) {
	b, h := newTestServer(t)
	req := httptest.NewRequest("POST", "http://127.0.0.1:7443/v1/decide",
		strings.NewReader(`{"user":"alice","agent_id":"cursor","resource":"prod","action":"write"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var res policy.Result
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Decision != policy.Deny || b.last.AgentID != "cursor" {
		t.Fatalf("res=%+v last=%+v", res, b.last)
	}
}

func TestGuardBlocksBrowsersAndRebinding(t *testing.T) {
	_, h := newTestServer(t)
	cases := []struct {
		name   string
		host   string
		header map[string]string
		ctype  string
		body   string
		want   int
	}{
		{"origin header", "127.0.0.1:7443", map[string]string{"Origin": "https://evil.example"}, "application/json", `{}`, 403},
		{"sec-fetch", "127.0.0.1:7443", map[string]string{"Sec-Fetch-Site": "cross-site"}, "application/json", `{}`, 403},
		{"dns rebinding host", "evil.example:7443", nil, "application/json", `{}`, 403},
		{"form post (simple CORS request)", "127.0.0.1:7443", nil, "text/plain", `{}`, 415},
		{"unknown field", "127.0.0.1:7443", nil, "application/json", `{"groups":["admin"]}`, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://"+c.host+"/v1/decide", strings.NewReader(c.body))
			req.Host = c.host
			req.Header.Set("Content-Type", c.ctype)
			for k, v := range c.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("status %d want %d", rec.Code, c.want)
			}
		})
	}
}
