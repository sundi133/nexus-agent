// Package localapi exposes the agent's policy decision point on loopback so
// on-device enforcement points (an MCP gateway/proxy, IDE plugins, shell
// wrappers) can ask "may this AI agent do X to resource Y?".
//
//	POST /v1/decide     policy.Request  → policy.Result
//	GET  /v1/ai-agents  latest AI agent detections
//	GET  /v1/status     agent health
//	GET  /healthz       liveness
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sundi133/nexus-agent/internal/detector"
	"github.com/sundi133/nexus-agent/internal/policy"
)

// Backend is implemented by the agent.
type Backend interface {
	Decide(ctx context.Context, req policy.Request) policy.Result
	AIAgents() []detector.DetectedAgent
	Status() any
}

// Server is the loopback HTTP server.
type Server struct {
	addr    string
	backend Backend
	log     *slog.Logger
}

// New validates that addr is a loopback address and builds a server.
func New(addr string, b Backend, log *slog.Logger) (*Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid local_api_addr %q: %w", addr, err)
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("local_api_addr must be a loopback address, got %q", host)
		}
	}
	return &Server{addr: addr, backend: b, log: log}, nil
}

// Handler returns the HTTP handler (exported for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.backend.Status())
	})
	mux.HandleFunc("GET /v1/ai-agents", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"agents": s.backend.AIAgents()})
	})
	mux.HandleFunc("POST /v1/decide", s.decide)
	return guard(mux)
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var req policy.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.backend.Decide(r.Context(), req))
}

// guard blocks browser-originated requests. Loopback alone is not enough: a
// malicious web page could POST to 127.0.0.1 or use DNS rebinding.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			http.Error(w, "browser requests are not allowed", http.StatusForbidden)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); !(host == "localhost" || (ip != nil && ip.IsLoopback())) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Serve listens until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	s.log.Info("local decision api listening", "addr", ln.Addr().String())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
