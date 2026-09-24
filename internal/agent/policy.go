package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/policy"
)

// syncPolicy fetches the policy bundle (ETag-aware) and activates it.
func (a *Agent) syncPolicy(ctx context.Context) error {
	_, etag := a.policies.Get()
	bundle, newETag, err := a.client.FetchPolicy(ctx, etag)
	if errors.Is(err, api.ErrNotModified) {
		a.markSync("policy")
		return nil
	}
	if err != nil {
		return a.handleAuthError(ctx, err)
	}
	if err := a.policies.Set(bundle, newETag); err != nil {
		// Keep enforcing the previous valid bundle.
		return err
	}
	a.markSync("policy")
	a.log.Info("policy updated", "version", bundle.Version, "policies", len(bundle.Policies))
	return nil
}

// Decide evaluates a local access request (called by the local API, e.g.
// from an MCP gateway sitting between an AI client and its tools) and
// records the decision for audit.
func (a *Agent) Decide(ctx context.Context, req policy.Request) policy.Result {
	// Fill in the agent category from the registry when the caller only
	// knows the product ID ("cursor" → "ai_coding_agent").
	if req.AgentType == "" && req.AgentID != "" {
		for _, d := range a.registry.Agents {
			if strings.EqualFold(d.ID, req.AgentID) {
				req.AgentType = d.Category
				break
			}
		}
	}
	bundle, _ := a.policies.Get()
	res := policy.Evaluate(bundle, policy.Environment{OS: a.plat.OS()}, req)

	data, _ := json.Marshal(struct {
		Request policy.Request `json:"request"`
		Result  policy.Result  `json:"result"`
	}{req, res})
	a.buffer.Add(api.Event{
		DeviceID:  a.DeviceID(),
		Timestamp: time.Now().UTC(),
		Type:      api.EventPolicyDecision,
		Source:    "policy_engine",
		Data:      data,
	})
	if res.Decision == policy.Deny {
		a.log.Info("policy denied request", "user", req.User, "agent", req.AgentID,
			"resource", req.Resource, "action", req.Action, "policy", res.PolicyID)
	}
	return res
}
