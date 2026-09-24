package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/config"
	"github.com/sundi133/nexus-agent/internal/policy"
)

// fakeCloud is a minimal Votal cloud for agent tests.
type fakeCloud struct {
	mu        sync.Mutex
	enrolls   int
	token     string
	bundle    policy.Bundle
	commands  []api.Command
	results   map[string]api.CommandResult
	events    []api.Event
	policyHit int
	notMod    int
	blob      []byte
}

func newFakeCloud() *fakeCloud {
	return &fakeCloud{
		token:   "tok-1",
		results: map[string]api.CommandResult{},
		bundle: policy.Bundle{
			Version: "v1",
			Device:  policy.DeviceContext{Managed: true},
			Policies: []policy.Policy{{
				ID: "p1", Name: "no writes", Conditions: policy.Conditions{Agent: &policy.AgentConditions{Type: "ai_agent"}},
				Resources: []string{"prod"}, Actions: []string{"read"}, Deny: []string{"write"},
			}},
		},
	}
}

func (f *fakeCloud) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			ok := r.Header.Get("Authorization") == "Bearer "+f.token
			f.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req api.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.EnrollmentToken != "enroll-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if len(req.HardwareID) != 64 {
			t.Errorf("hardware id should be a sha256 hex digest, got %q", req.HardwareID)
		}
		f.mu.Lock()
		f.enrolls++
		f.mu.Unlock()
		json.NewEncoder(w).Encode(api.EnrollResponse{DeviceID: "dev_1", AgentToken: f.token, OrgID: "org_1"})
	})
	mux.HandleFunc("GET /v1/devices/dev_1/policy", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.policyHit++
		etag := `"` + f.bundle.Version + `"`
		if r.Header.Get("If-None-Match") == etag {
			f.notMod++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		json.NewEncoder(w).Encode(f.bundle)
	}))
	mux.HandleFunc("GET /v1/devices/dev_1/commands", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"commands": f.commands})
	}))
	mux.HandleFunc("POST /v1/devices/dev_1/commands/{id}/result", authed(func(w http.ResponseWriter, r *http.Request) {
		var res api.CommandResult
		json.NewDecoder(r.Body).Decode(&res)
		f.mu.Lock()
		f.results[r.PathValue("id")] = res
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /v1/devices/dev_1/telemetry", authed(func(w http.ResponseWriter, r *http.Request) {
		var b api.TelemetryBatch
		json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.events = append(f.events, b.Events...)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	mux.HandleFunc("GET /blob", authed(func(w http.ResponseWriter, r *http.Request) {
		w.Write(f.blob)
	}))
	return mux
}

func newTestAgent(t *testing.T, serverURL string) *Agent {
	t.Helper()
	cfg := config.Default()
	cfg.ServerURL = serverURL
	cfg.AllowInsecureHTTP = true
	cfg.EnrollmentToken = "enroll-secret"
	cfg.StateDir = t.TempDir()
	cfg.OsqueryPath = "disabled"
	cfg.LocalAPIAddr = ""
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnrollPersistsIdentity(t *testing.T) {
	cloud := newFakeCloud()
	srv := httptest.NewServer(cloud.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	ctx := context.Background()

	if err := a.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	if a.DeviceID() != "dev_1" {
		t.Fatalf("device id %q", a.DeviceID())
	}
	st, err := os.Stat(a.identityPath())
	if err != nil {
		t.Fatal(err)
	}
	if os.PathSeparator == '/' && st.Mode().Perm() != 0o600 {
		t.Errorf("identity perms %v, want 0600", st.Mode().Perm())
	}

	// A second agent on the same state dir reuses the identity.
	b, _ := New(a.cfg, a.log)
	if err := b.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	if cloud.enrolls != 1 {
		t.Fatalf("expected 1 enrollment, got %d", cloud.enrolls)
	}
}

func TestEnrollBadTokenFailsFast(t *testing.T) {
	srv := httptest.NewServer(newFakeCloud().handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	a.cfg.EnrollmentToken = "wrong"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Enroll(ctx); err == nil || !strings.Contains(err.Error(), "enrollment rejected") {
		t.Fatalf("got %v", err)
	}
}

func TestPolicySyncETagAndDecide(t *testing.T) {
	cloud := newFakeCloud()
	srv := httptest.NewServer(cloud.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	ctx := context.Background()
	if err := a.Enroll(ctx); err != nil {
		t.Fatal(err)
	}

	// Before any policy: fail closed.
	if r := a.Decide(ctx, policy.Request{AgentID: "cursor", Resource: "prod", Action: "read"}); r.Decision != policy.Deny {
		t.Fatalf("no bundle should deny: %+v", r)
	}
	if err := a.syncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.syncPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if cloud.notMod != 1 {
		t.Fatalf("second sync should be 304, got notMod=%d", cloud.notMod)
	}

	// agent_id is resolved to its registry category ("cursor" → ai_coding_agent).
	if r := a.Decide(ctx, policy.Request{AgentID: "cursor", Resource: "prod", Action: "write"}); r.Decision != policy.Deny || r.PolicyID != "p1" {
		t.Fatalf("write: %+v", r)
	}
	if r := a.Decide(ctx, policy.Request{AgentID: "cursor", Resource: "prod", Action: "read"}); r.Decision != policy.Allow {
		t.Fatalf("read: %+v", r)
	}

	// Decisions are audited to the cloud.
	if err := a.flushTelemetry(ctx); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range cloud.events {
		if e.Type == api.EventPolicyDecision {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want 3 audited decisions, got %d", n)
	}
}

func TestCommandsAllowListAndIdempotency(t *testing.T) {
	cloud := newFakeCloud()
	cloud.commands = []api.Command{
		{ID: "c1", Type: api.CmdRefreshPolicy},
		{ID: "c2", Type: "run_shell", Args: json.RawMessage(`{"cmd":"rm -rf /"}`)},
		{ID: "c3", Type: api.CmdCollectTelemetry, ExpiresAt: time.Now().Add(-time.Minute)},
		{ID: "c4", Type: api.CmdOsqueryQuery, Args: json.RawMessage(`{"sql":"SELECT 1"}`)},
	}
	srv := httptest.NewServer(cloud.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	ctx := context.Background()
	if err := a.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.pollCommands(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"c1": "ok", "c2": "rejected", "c3": "rejected", "c4": "error"}
	for id, status := range want {
		if got := cloud.results[id].Status; got != status {
			t.Errorf("%s: status %q want %q (%s)", id, got, status, cloud.results[id].Error)
		}
	}
	select {
	case <-a.kickPolicy:
	default:
		t.Error("refresh_policy did not trigger policy loop")
	}

	// Re-delivered commands are not executed twice.
	cloud.results = map[string]api.CommandResult{}
	if err := a.pollCommands(ctx); err != nil {
		t.Fatal(err)
	}
	if len(cloud.results) != 0 {
		t.Fatalf("commands re-executed: %v", cloud.results)
	}
}

func TestReenrollAfterRepeatedUnauthorized(t *testing.T) {
	cloud := newFakeCloud()
	srv := httptest.NewServer(cloud.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	ctx := context.Background()
	if err := a.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	// Cloud rotates the token (e.g. device re-approved in console).
	cloud.mu.Lock()
	cloud.token = "tok-2"
	cloud.mu.Unlock()
	for i := 0; i < 3; i++ {
		_ = a.syncPolicy(ctx)
	}
	if cloud.enrolls != 2 {
		t.Fatalf("expected re-enrollment, enrolls=%d", cloud.enrolls)
	}
	if err := a.syncPolicy(ctx); err != nil {
		t.Fatalf("after re-enroll: %v", err)
	}
}

func TestDownloadVerified(t *testing.T) {
	cloud := newFakeCloud()
	cloud.blob = []byte("new agent binary")
	srv := httptest.NewServer(cloud.handler(t))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	ctx := context.Background()
	if err := a.Enroll(ctx); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha256.Sum256(cloud.blob)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))
	dir := t.TempDir()

	path, err := a.downloadVerified(ctx, "/blob", hex.EncodeToString(digest[:]), sig, pub, dir)
	if err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, cloud.blob) {
		t.Fatal("staged content mismatch")
	}

	// Signature from a different key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	badSig := base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, digest[:]))
	if _, err := a.downloadVerified(ctx, "/blob", hex.EncodeToString(digest[:]), badSig, pub, dir); err == nil {
		t.Fatal("forged signature accepted")
	}

	// Server swaps the binary after signing.
	cloud.blob = []byte("malicious binary")
	if _, err := a.downloadVerified(ctx, "/blob", hex.EncodeToString(digest[:]), sig, pub, dir); err == nil {
		t.Fatal("tampered binary accepted")
	}

	// Absolute non-https URLs are refused.
	if _, err := a.downloadVerified(ctx, "http://evil.example/blob", hex.EncodeToString(digest[:]), sig, pub, dir); err == nil {
		t.Fatal("plain http download accepted")
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("failed downloads left temp files: %v", entries)
	}
}

func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "votal-agent")
	staged := filepath.Join(dir, "staged")
	os.WriteFile(exe, []byte("old"), 0o755)
	os.WriteFile(staged, []byte("new"), 0o755)
	if err := replaceExecutable(exe, staged); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("exe = %q", b)
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "old" {
		t.Fatalf("backup = %q", b)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.10.0", "1.9.9", 1},
		{"v2.0.0", "1.99.99", 1},
		{"1.2", "1.2.1", -1},
		{"1.3.0-rc1", "1.2.9", 1},
		{"0.0.0-dev", "0.1.0", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestJitterAndBackoffBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := jitter(100 * time.Second)
		if d < 90*time.Second || d > 110*time.Second {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
	b := newBackoff(time.Second, 8*time.Second)
	for i := 0; i < 10; i++ {
		if d := b.next(); d > 8*time.Second {
			t.Fatalf("backoff exceeded max: %v", d)
		}
	}
}
