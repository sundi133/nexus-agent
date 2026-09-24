// Package policy evaluates Votal access policies on-device.
//
// Policies are authored and versioned in the Votal cloud and distributed to
// agents as a Bundle. The agent only *evaluates* them (so decisions work
// offline and in microseconds); it never authors them.
//
// Semantics:
//  1. A policy applies when all of its conditions (device, user, agent) and
//     its resource/tool selectors match the request.
//  2. Any applicable policy in "enforce" mode that denies the action → DENY.
//     (Deny always wins.)
//  3. Otherwise, any applicable policy that allows the action → ALLOW.
//  4. Otherwise the bundle's default decision applies.
//
// Policies in "monitor" mode never block; a would-be deny is reported in the
// decision so admins can trial a policy before enforcing it.
package policy

import (
	"fmt"
	"strings"
)

// Decision values.
const (
	Allow = "allow"
	Deny  = "deny"
)

// Modes.
const (
	ModeEnforce = "enforce"
	ModeMonitor = "monitor"
)

// AnyAIAgent matches every AI agent category in AgentConditions.Types.
const AnyAIAgent = "ai_agent"

// Bundle is the full policy document delivered to a device.
type Bundle struct {
	Version         string        `json:"version"`
	DefaultDecision string        `json:"default_decision"`
	Device          DeviceContext `json:"device"`
	// Directory maps usernames to groups, synced by the cloud from the IdP.
	// Group membership is never taken from the caller of the decision API.
	Directory map[string][]string `json:"directory,omitempty"`
	Policies  []Policy            `json:"policies"`
}

// DeviceContext is what the cloud knows about this device.
type DeviceContext struct {
	Managed   bool     `json:"managed"`
	Groups    []string `json:"groups,omitempty"`
	RiskScore int      `json:"risk_score"`
}

// Policy is one rule.
type Policy struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Mode       string     `json:"mode,omitempty"` // enforce (default) | monitor
	Conditions Conditions `json:"conditions"`
	// Resources and Tools are wildcard patterns, case-insensitive: "*"
	// matches any run of characters (including "/" and ":"), "?" one
	// character. Empty means "any".
	Resources []string `json:"resources,omitempty"`
	Tools     []string `json:"tools,omitempty"`
	// Actions lists allowed actions; Deny lists denied actions. "*" matches all.
	Actions []string `json:"actions,omitempty"`
	Deny    []string `json:"deny,omitempty"`
}

// Conditions scope a policy. Nil sections match everything.
type Conditions struct {
	Device *DeviceConditions `json:"device,omitempty"`
	User   *UserConditions   `json:"user,omitempty"`
	Agent  *AgentConditions  `json:"agent,omitempty"`
}

// DeviceConditions match on device state.
type DeviceConditions struct {
	Managed      *bool    `json:"managed,omitempty"`
	OS           []string `json:"os,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	MaxRiskScore *int     `json:"max_risk_score,omitempty"`
}

// UserConditions match on identity.
type UserConditions struct {
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// Group is accepted for the single-group shorthand used in docs.
	Group string `json:"group,omitempty"`
}

// AgentConditions match on the AI agent making the call.
type AgentConditions struct {
	Types []string `json:"types,omitempty"`
	Type  string   `json:"type,omitempty"` // shorthand
	IDs   []string `json:"ids,omitempty"`
}

// Request is an access decision query, e.g. from an MCP gateway/proxy.
type Request struct {
	User      string `json:"user"`
	AgentID   string `json:"agent_id,omitempty"`   // e.g. "cursor"
	AgentType string `json:"agent_type,omitempty"` // e.g. "ai_coding_agent"
	Tool      string `json:"tool,omitempty"`       // e.g. "postgres.query"
	Resource  string `json:"resource"`             // e.g. "production_database"
	Action    string `json:"action"`               // e.g. "write"
}

// Result is the outcome of an evaluation.
type Result struct {
	Decision   string `json:"decision"`
	PolicyID   string `json:"policy_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	Reason     string `json:"reason"`
	// MonitorDeny is set when a monitor-mode policy would have denied.
	MonitorDeny   bool   `json:"monitor_deny,omitempty"`
	MonitorPolicy string `json:"monitor_policy,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
}

// Environment is local device state not carried in the bundle.
type Environment struct {
	OS string // "macos" | "windows" | "linux"
}

// Validate checks a bundle for structural errors.
func (b *Bundle) Validate() error {
	switch b.DefaultDecision {
	case "", Allow, Deny:
	default:
		return fmt.Errorf("default_decision must be %q or %q", Allow, Deny)
	}
	ids := map[string]bool{}
	for i, p := range b.Policies {
		if p.ID == "" {
			return fmt.Errorf("policy %d: id is required", i)
		}
		if ids[p.ID] {
			return fmt.Errorf("policy %s: duplicate id", p.ID)
		}
		ids[p.ID] = true
		switch p.Mode {
		case "", ModeEnforce, ModeMonitor:
		default:
			return fmt.Errorf("policy %s: invalid mode %q", p.ID, p.Mode)
		}
		if len(p.Actions) == 0 && len(p.Deny) == 0 {
			return fmt.Errorf("policy %s: must list actions or deny", p.ID)
		}
		for _, pat := range append(append([]string{}, p.Resources...), p.Tools...) {
			if strings.TrimSpace(pat) == "" {
				return fmt.Errorf("policy %s: empty resource/tool pattern", p.ID)
			}
		}
	}
	return nil
}

// Evaluate decides a request against a bundle. A nil bundle denies
// everything: an agent with no policy must fail closed.
func Evaluate(b *Bundle, env Environment, req Request) Result {
	if b == nil {
		return Result{Decision: Deny, Reason: "no policy bundle loaded"}
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Action == "" || req.Resource == "" {
		return Result{Decision: Deny, Reason: "request must include resource and action", BundleVersion: b.Version}
	}
	userGroups := b.Directory[req.User]

	var allowBy, monitorDenyBy *Policy
	for i := range b.Policies {
		p := &b.Policies[i]
		if !p.applies(b, env, userGroups, req) {
			continue
		}
		if matchAny(p.Deny, req.Action) {
			if p.Mode == ModeMonitor {
				if monitorDenyBy == nil {
					monitorDenyBy = p
				}
				continue
			}
			return Result{
				Decision:      Deny,
				PolicyID:      p.ID,
				PolicyName:    p.Name,
				Reason:        fmt.Sprintf("action %q denied by policy %q", req.Action, p.Name),
				BundleVersion: b.Version,
			}
		}
		if allowBy == nil && matchAny(p.Actions, req.Action) {
			allowBy = p
		}
	}

	var res Result
	switch {
	case allowBy != nil:
		res = Result{Decision: Allow, PolicyID: allowBy.ID, PolicyName: allowBy.Name,
			Reason: fmt.Sprintf("action %q allowed by policy %q", req.Action, allowBy.Name)}
	case b.DefaultDecision == Deny:
		res = Result{Decision: Deny, Reason: "no policy allows this action (default deny)"}
	default:
		res = Result{Decision: Allow, Reason: "no policy matched (default allow)"}
	}
	if monitorDenyBy != nil {
		res.MonitorDeny = true
		res.MonitorPolicy = monitorDenyBy.ID
		res.Reason += fmt.Sprintf("; monitor-mode policy %q would deny", monitorDenyBy.Name)
	}
	res.BundleVersion = b.Version
	return res
}

func (p *Policy) applies(b *Bundle, env Environment, userGroups []string, req Request) bool {
	if c := p.Conditions.Device; c != nil {
		if c.Managed != nil && *c.Managed != b.Device.Managed {
			return false
		}
		if len(c.OS) > 0 && !containsFold(c.OS, env.OS) {
			return false
		}
		if len(c.Groups) > 0 && !intersects(c.Groups, b.Device.Groups) {
			return false
		}
		if c.MaxRiskScore != nil && b.Device.RiskScore > *c.MaxRiskScore {
			return false
		}
	}
	if c := p.Conditions.User; c != nil {
		groups := c.Groups
		if c.Group != "" {
			groups = append(append([]string{}, groups...), c.Group)
		}
		if len(c.Users) > 0 && !containsFold(c.Users, req.User) {
			return false
		}
		if len(groups) > 0 && !intersects(groups, userGroups) {
			return false
		}
	}
	if c := p.Conditions.Agent; c != nil {
		types := c.Types
		if c.Type != "" {
			types = append(append([]string{}, types...), c.Type)
		}
		if len(types) > 0 && !agentTypeMatches(types, req.AgentType) {
			return false
		}
		if len(c.IDs) > 0 && !containsFold(c.IDs, req.AgentID) {
			return false
		}
	}
	if len(p.Resources) > 0 && !matchAny(p.Resources, req.Resource) {
		return false
	}
	if len(p.Tools) > 0 && !matchAny(p.Tools, req.Tool) {
		return false
	}
	return true
}

func agentTypeMatches(types []string, t string) bool {
	if t == "" {
		return false
	}
	for _, x := range types {
		if x == "*" || strings.EqualFold(x, t) || (x == AnyAIAgent && t != "") {
			return true
		}
	}
	return false
}

// matchAny reports whether v matches any wildcard pattern (case-insensitive).
func matchAny(patterns []string, v string) bool {
	v = strings.ToLower(v)
	for _, p := range patterns {
		if wildcardMatch(strings.ToLower(p), v) {
			return true
		}
	}
	return false
}

// wildcardMatch matches s against p where '*' is any sequence and '?' any
// single byte. Linear-time greedy matching with single-star backtracking.
func wildcardMatch(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if containsFold(b, x) {
			return true
		}
	}
	return false
}
