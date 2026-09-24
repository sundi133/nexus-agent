// Package agent is the cross-platform core of the Votal endpoint agent.
//
// The agent is deliberately "dumb and reliable": it enrolls, reports
// heartbeat and telemetry, caches the policy bundle the cloud computes, runs
// a small allow-list of commands, and answers local policy-decision queries.
// Policy authoring, RBAC, risk scoring and dashboards live in the cloud.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/config"
	"github.com/sundi133/nexus-agent/internal/detector"
	"github.com/sundi133/nexus-agent/internal/localapi"
	"github.com/sundi133/nexus-agent/internal/osquery"
	"github.com/sundi133/nexus-agent/internal/platform"
	"github.com/sundi133/nexus-agent/internal/policy"
	"github.com/sundi133/nexus-agent/internal/secure"
	"github.com/sundi133/nexus-agent/internal/telemetry"
	"github.com/sundi133/nexus-agent/internal/version"
)

// ErrRestartRequired is returned by Run after a self-update was staged; the
// service manager (launchd / SCM / systemd) restarts the new binary.
var ErrRestartRequired = errors.New("restart required to apply update")

// Agent wires all components together.
type Agent struct {
	cfg       *config.Config
	log       *slog.Logger
	plat      platform.Platform
	client    *api.Client
	osq       *osquery.Manager
	registry  *detector.Registry
	collector *telemetry.Collector
	policies  *policy.Store
	buffer    *telemetry.Buffer
	started   time.Time

	kickTelemetry chan struct{}
	kickPolicy    chan struct{}
	kickCommands  chan struct{}
	kickUpdate    chan struct{}
	restart       chan struct{}

	mu       sync.RWMutex
	identity *Identity
	aiAgents []detector.DetectedAgent
	lastSync map[string]time.Time
	executed map[string]time.Time // command IDs already run (idempotency)
	authFail int
}

// New builds an agent from config.
func New(cfg *config.Config, log *slog.Logger) (*Agent, error) {
	if err := secure.RestrictDir(cfg.StateDir); err != nil {
		return nil, fmt.Errorf("secure state dir: %w", err)
	}
	client, err := api.NewClient(api.Options{
		BaseURL:   cfg.ServerURL,
		CAFile:    cfg.CAFile,
		UserAgent: "votal-agent/" + version.Version + " (" + version.Platform() + ")",
	})
	if err != nil {
		return nil, err
	}
	store, err := policy.NewStore(filepath.Join(cfg.StateDir, "policy.json"))
	if err != nil {
		return nil, fmt.Errorf("load policy cache: %w", err)
	}
	plat := platform.New()
	osq := osquery.New(cfg.OsqueryPath)
	reg := detector.BuiltinRegistry()
	a := &Agent{
		cfg:           cfg,
		log:           log,
		plat:          plat,
		client:        client,
		osq:           osq,
		registry:      reg,
		collector:     telemetry.NewCollector(plat, osq, detector.New(reg), log),
		policies:      store,
		buffer:        telemetry.NewBuffer(5000),
		kickTelemetry: make(chan struct{}, 1),
		kickPolicy:    make(chan struct{}, 1),
		kickCommands:  make(chan struct{}, 1),
		kickUpdate:    make(chan struct{}, 1),
		restart:       make(chan struct{}, 1),
		lastSync:      map[string]time.Time{},
		executed:      map[string]time.Time{},
	}
	return a, nil
}

// Run enrolls and then runs all loops until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.started = time.Now()
	a.log.Info("starting", "version", version.String(), "os", a.plat.OS(),
		"server", a.cfg.ServerURL, "osquery", a.osq.Path())

	// The local decision API starts before enrollment so cached policy keeps
	// protecting the device even if the cloud is unreachable at boot.
	if a.cfg.LocalAPIAddr != "" {
		srv, err := localapi.New(a.cfg.LocalAPIAddr, a, a.log)
		if err != nil {
			return fmt.Errorf("local api: %w", err)
		}
		go func() {
			if err := srv.Serve(ctx); err != nil {
				a.log.Error("local api stopped", "err", err)
			}
		}()
	}

	if err := a.Enroll(ctx); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	start := func(name string, interval time.Duration, kick chan struct{}, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.loop(ctx, name, interval, kick, fn)
		}()
	}
	iv := a.cfg.Intervals
	start("heartbeat", iv.Heartbeat.Duration, nil, a.heartbeat)
	start("policy", iv.Policy.Duration, a.kickPolicy, a.syncPolicy)
	start("telemetry", iv.Telemetry.Duration, a.kickTelemetry, a.collectAndUpload)
	start("commands", iv.Commands.Duration, a.kickCommands, a.pollCommands)
	start("updates", iv.Updates.Duration, a.kickUpdate, a.checkUpdate)

	var result error
	select {
	case <-ctx.Done():
	case <-a.restart:
		result = ErrRestartRequired
	}
	cancel()
	wg.Wait()
	// Best-effort final flush, bounded so a dead network cannot block stop.
	fctx, fcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer fcancel()
	if err := a.flushTelemetry(fctx); err != nil {
		a.log.Warn("final telemetry flush failed", "err", err)
	}
	a.log.Info("stopped")
	return result
}

// handleAuthError re-enrolls after repeated 401s (e.g. the device was
// removed in the console and re-approved, or the token was rotated).
func (a *Agent) handleAuthError(ctx context.Context, err error) error {
	if !errors.Is(err, api.ErrUnauthorized) {
		a.mu.Lock()
		a.authFail = 0
		a.mu.Unlock()
		return err
	}
	a.mu.Lock()
	a.authFail++
	n := a.authFail
	a.mu.Unlock()
	if n >= 3 && a.cfg.EnrollmentToken != "" {
		if rerr := a.reenroll(ctx); rerr != nil {
			return fmt.Errorf("re-enroll: %w", rerr)
		}
		a.mu.Lock()
		a.authFail = 0
		a.mu.Unlock()
	}
	return err
}

func (a *Agent) markSync(name string) {
	a.mu.Lock()
	a.lastSync[name] = time.Now().UTC()
	a.mu.Unlock()
}

// Status is exposed on the local API for troubleshooting.
func (a *Agent) Status() any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	bundle, _ := a.policies.Get()
	pv := ""
	if bundle != nil {
		pv = bundle.Version
	}
	sync := make(map[string]time.Time, len(a.lastSync))
	for k, v := range a.lastSync {
		sync[k] = v
	}
	return map[string]any{
		"version":          version.Version,
		"platform":         version.Platform(),
		"device_id":        a.deviceIDLocked(),
		"enrolled":         a.identity != nil,
		"policy_version":   pv,
		"osquery":          a.osq.Available(),
		"uptime_seconds":   int64(time.Since(a.started).Seconds()),
		"queued_events":    a.buffer.Len(),
		"dropped_events":   a.buffer.Dropped(),
		"last_sync":        sync,
		"ai_agents_active": len(a.aiAgents),
	}
}

// deviceIDLocked returns the device ID; caller must hold a.mu.
func (a *Agent) deviceIDLocked() string {
	if a.identity == nil {
		return ""
	}
	return a.identity.DeviceID
}

// AIAgents returns the most recent AI agent detections.
func (a *Agent) AIAgents() []detector.DetectedAgent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]detector.DetectedAgent(nil), a.aiAgents...)
}
