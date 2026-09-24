package agent

import (
	"context"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/version"
)

// heartbeat reports liveness and reacts to cloud nudges.
func (a *Agent) heartbeat(ctx context.Context) error {
	bundle, _ := a.policies.Get()
	pv := ""
	if bundle != nil {
		pv = bundle.Version
	}
	resp, err := a.client.Heartbeat(ctx, api.HeartbeatRequest{
		AgentVersion:  version.Version,
		Timestamp:     time.Now().UTC(),
		Uptime:        int64(time.Since(a.started).Seconds()),
		PolicyVersion: pv,
		ConsoleUser:   a.plat.ConsoleUser(ctx),
	})
	if err != nil {
		return a.handleAuthError(ctx, err)
	}
	a.handleAuthError(ctx, nil)
	a.markSync("heartbeat")
	if resp.PolicyVersion != "" && resp.PolicyVersion != pv {
		trigger(a.kickPolicy)
	}
	if resp.PendingCommands {
		trigger(a.kickCommands)
	}
	return nil
}
