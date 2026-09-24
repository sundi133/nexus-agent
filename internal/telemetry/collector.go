// Package telemetry gathers device state from the platform module, osquery
// and the AI detector, and normalizes it into Votal telemetry events.
package telemetry

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/detector"
	"github.com/sundi133/nexus-agent/internal/osquery"
	"github.com/sundi133/nexus-agent/internal/platform"
)

// Collector produces telemetry snapshots.
type Collector struct {
	Platform platform.Platform
	Osquery  *osquery.Manager
	Detector *detector.Detector
	Log      *slog.Logger
	now      func() time.Time
}

// Result is one full collection pass.
type Result struct {
	Events   []api.Event
	AIAgents []detector.DetectedAgent
}

// NewCollector wires a collector.
func NewCollector(p platform.Platform, oq *osquery.Manager, d *detector.Detector, log *slog.Logger) *Collector {
	return &Collector{Platform: p, Osquery: oq, Detector: d, Log: log, now: time.Now}
}

// Collect runs every probe. Individual failures are logged and skipped so
// one broken OS tool never drops the whole snapshot.
func (c *Collector) Collect(ctx context.Context, deviceID string) Result {
	ts := c.now().UTC()
	var res Result
	emit := func(typ, source string, data any) {
		b, err := json.Marshal(data)
		if err != nil {
			c.Log.Warn("telemetry marshal failed", "type", typ, "err", err)
			return
		}
		res.Events = append(res.Events, api.Event{DeviceID: deviceID, Timestamp: ts, Type: typ, Source: source, Data: b})
	}

	if info, err := c.Platform.DeviceInfo(ctx); err == nil {
		emit(api.EventDeviceInfo, "platform", info)
	} else {
		c.Log.Warn("device info failed", "err", err)
	}

	if posture, err := c.Platform.SecurityPosture(ctx); err == nil {
		emit(api.EventPosture, "platform", posture)
	} else {
		c.Log.Warn("posture failed", "err", err)
	}

	procs, err := c.Platform.Processes(ctx)
	if err != nil {
		c.Log.Warn("process inventory failed", "err", err)
	} else {
		emit(api.EventProcesses, "platform", map[string]any{"count": len(procs), "processes": procs})
	}

	conns, err := c.Platform.NetworkConnections(ctx)
	if err != nil {
		c.Log.Warn("network inventory failed", "err", err)
	} else {
		emit(api.EventConnections, "platform", map[string]any{"count": len(conns), "connections": conns})
	}

	apps, source := c.applications(ctx)
	emit(api.EventApplications, source, map[string]any{"count": len(apps), "applications": apps})

	if c.Detector != nil {
		snap := detector.Snapshot{
			OS:          c.Platform.OS(),
			Processes:   procs,
			Apps:        apps,
			Connections: conns,
			HomeDirs:    c.Platform.UserHomeDirs(),
		}
		res.AIAgents = c.Detector.Detect(snap)
		emit(api.EventAIAgents, "detector", map[string]any{"count": len(res.AIAgents), "agents": res.AIAgents})
		emit(api.EventAIAgentGraph, "detector", detector.BuildGraph(deviceID, res.AIAgents))
	}
	return res
}

// applications prefers osquery (richer, battle-tested) and falls back to
// the native platform implementation.
func (c *Collector) applications(ctx context.Context) ([]platform.Application, string) {
	if c.Osquery.Available() {
		rows, err := c.Osquery.Query(ctx, osquery.AppsQuery())
		if err == nil {
			apps := make([]platform.Application, 0, len(rows))
			for _, r := range rows {
				src := r["source"]
				if src == "" {
					src = "osquery"
				}
				apps = append(apps, platform.Application{
					Name: r["name"], Version: r["version"], Path: r["path"],
					Publisher: r["publisher"], BundleID: r["bundle_id"], Source: src,
				})
			}
			return apps, "osquery"
		}
		c.Log.Warn("osquery app inventory failed; using native", "err", err)
	}
	apps, err := c.Platform.InstalledApps(ctx)
	if err != nil {
		c.Log.Warn("app inventory failed", "err", err)
	}
	return apps, "platform"
}
