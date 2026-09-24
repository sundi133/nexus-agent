// Command votal-devserver is an in-memory stand-in for the Votal cloud API,
// for local development and end-to-end tests of the agent. It is NOT a
// production server: state is in memory and there is no persistence or RBAC.
//
//	votal-devserver -addr 127.0.0.1:8080 -enroll-token dev-token -policy examples/policy.json
//
// Admin endpoints (no auth, dev only):
//
//	GET  /admin/devices
//	GET  /admin/events?device=ID&type=TYPE
//	POST /admin/devices/{id}/commands   {"type":"osquery_query","args":{"sql":"SELECT ..."}}
//	GET  /admin/results
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/policy"
)

type device struct {
	ID        string          `json:"id"`
	Token     string          `json:"-"`
	Info      json.RawMessage `json:"info"`
	Hardware  string          `json:"hardware_id"`
	Version   string          `json:"agent_version"`
	LastSeen  time.Time       `json:"last_seen"`
	Enrolled  time.Time       `json:"enrolled_at"`
	Heartbeat int             `json:"heartbeats"`
	commands  []api.Command
}

type server struct {
	mu          sync.Mutex
	enrollToken string
	bundle      *policy.Bundle
	devices     map[string]*device
	byToken     map[string]*device
	events      []api.Event
	results     []map[string]any
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	token := flag.String("enroll-token", "dev-token", "accepted enrollment token")
	policyPath := flag.String("policy", "examples/policy.json", "policy bundle served to all devices")
	flag.Parse()

	s := &server{enrollToken: *token, devices: map[string]*device{}, byToken: map[string]*device{}}
	if b, err := os.ReadFile(*policyPath); err == nil {
		var bundle policy.Bundle
		if err := json.Unmarshal(b, &bundle); err != nil {
			log.Fatalf("parse policy: %v", err)
		}
		if err := bundle.Validate(); err != nil {
			log.Fatalf("invalid policy: %v", err)
		}
		s.bundle = &bundle
	} else {
		log.Printf("no policy file (%v); serving empty bundle", err)
		s.bundle = &policy.Bundle{Version: "empty", DefaultDecision: policy.Allow}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/devices/{id}/heartbeat", s.auth(s.heartbeat))
	mux.HandleFunc("POST /v1/devices/{id}/telemetry", s.auth(s.telemetry))
	mux.HandleFunc("GET /v1/devices/{id}/policy", s.auth(s.policy))
	mux.HandleFunc("GET /v1/devices/{id}/commands", s.auth(s.commands))
	mux.HandleFunc("POST /v1/devices/{id}/commands/{cid}/result", s.auth(s.result))
	mux.HandleFunc("GET /v1/agent/update", s.auth(func(w http.ResponseWriter, r *http.Request, d *device) {
		writeJSON(w, api.UpdateInfo{Available: false})
	}))
	mux.HandleFunc("GET /admin/devices", s.adminDevices)
	mux.HandleFunc("GET /admin/events", s.adminEvents)
	mux.HandleFunc("POST /admin/devices/{id}/commands", s.adminCommand)
	mux.HandleFunc("GET /admin/results", s.adminResults)

	log.Printf("votal-devserver listening on http://%s (enroll token %q)", *addr, *token)
	log.Fatal(http.ListenAndServe(*addr, logRequests(mux)))
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollmentToken string          `json:"enrollment_token"`
		HardwareID      string          `json:"hardware_id"`
		Device          json.RawMessage `json:"device"`
		AgentVersion    string          `json:"agent_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.EnrollmentToken), []byte(s.enrollToken)) != 1 {
		http.Error(w, "invalid enrollment token", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-enrollment of the same hardware keeps the device ID.
	var d *device
	for _, x := range s.devices {
		if x.Hardware == req.HardwareID {
			d = x
			delete(s.byToken, x.Token)
		}
	}
	if d == nil {
		d = &device{ID: "dev_" + randHex(6), Hardware: req.HardwareID, Enrolled: time.Now().UTC()}
		s.devices[d.ID] = d
	}
	d.Token = "vat_" + randHex(24)
	d.Info, d.Version, d.LastSeen = req.Device, req.AgentVersion, time.Now().UTC()
	s.byToken[d.Token] = d
	log.Printf("enrolled %s", d.ID)
	writeJSON(w, api.EnrollResponse{DeviceID: d.ID, AgentToken: d.Token, OrgID: "org_dev"})
}

func (s *server) auth(next func(http.ResponseWriter, *http.Request, *device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		d := s.byToken[tok]
		s.mu.Unlock()
		if d == nil || (r.PathValue("id") != "" && r.PathValue("id") != d.ID) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, d)
	}
}

func (s *server) heartbeat(w http.ResponseWriter, r *http.Request, d *device) {
	var hb api.HeartbeatRequest
	_ = json.NewDecoder(r.Body).Decode(&hb)
	s.mu.Lock()
	d.LastSeen, d.Version = time.Now().UTC(), hb.AgentVersion
	d.Heartbeat++
	pending := len(d.commands) > 0
	s.mu.Unlock()
	writeJSON(w, api.HeartbeatResponse{PolicyVersion: s.bundle.Version, PendingCommands: pending})
}

func (s *server) telemetry(w http.ResponseWriter, r *http.Request, d *device) {
	var batch api.TelemetryBatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&batch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	counts := map[string]int{}
	s.mu.Lock()
	for _, e := range batch.Events {
		counts[e.Type]++
		s.events = append(s.events, e)
	}
	if len(s.events) > 10000 {
		s.events = s.events[len(s.events)-10000:]
	}
	s.mu.Unlock()
	log.Printf("telemetry from %s: %v", d.ID, counts)
	w.WriteHeader(http.StatusAccepted)
}

func (s *server) policy(w http.ResponseWriter, r *http.Request, d *device) {
	etag := `"` + s.bundle.Version + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	// Every enrolled device is "managed" in the dev server.
	b := *s.bundle
	b.Device.Managed = true
	writeJSON(w, b)
}

func (s *server) commands(w http.ResponseWriter, r *http.Request, d *device) {
	s.mu.Lock()
	cmds := d.commands
	d.commands = nil
	s.mu.Unlock()
	writeJSON(w, map[string]any{"commands": cmds})
}

func (s *server) result(w http.ResponseWriter, r *http.Request, d *device) {
	var res api.CommandResult
	_ = json.NewDecoder(r.Body).Decode(&res)
	s.mu.Lock()
	s.results = append(s.results, map[string]any{"device": d.ID, "command": r.PathValue("cid"), "result": res})
	s.mu.Unlock()
	log.Printf("command %s on %s: %s %s", r.PathValue("cid"), d.ID, res.Status, res.Error)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) adminDevices(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d)
	}
	writeJSON(w, out)
}

func (s *server) adminEvents(w http.ResponseWriter, r *http.Request) {
	dev, typ := r.URL.Query().Get("device"), r.URL.Query().Get("type")
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.Event
	for _, e := range s.events {
		if (dev == "" || e.DeviceID == dev) && (typ == "" || e.Type == typ) {
			out = append(out, e)
		}
	}
	writeJSON(w, out)
}

func (s *server) adminCommand(w http.ResponseWriter, r *http.Request) {
	var cmd api.Command
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[r.PathValue("id")]
	if d == nil {
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	cmd.ID = "cmd_" + randHex(6)
	cmd.IssuedAt = time.Now().UTC()
	d.commands = append(d.commands, cmd)
	writeJSON(w, cmd)
}

func (s *server) adminResults(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, s.results)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin") {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		h.ServeHTTP(w, r)
	})
}
