// Package api defines the wire protocol between the Votal agent and the
// Votal cloud, and an HTTP client for it.
//
// Endpoints (all JSON, all under the configured server URL):
//
//	POST /v1/enroll                              enrollment-token auth
//	POST /v1/devices/{id}/heartbeat              agent-token auth
//	POST /v1/devices/{id}/telemetry              agent-token auth
//	GET  /v1/devices/{id}/policy                 agent-token auth, ETag aware
//	GET  /v1/devices/{id}/commands               agent-token auth
//	POST /v1/devices/{id}/commands/{cid}/result  agent-token auth
//	GET  /v1/agent/update?os=&arch=&version=     agent-token auth
package api

import (
	"encoding/json"
	"time"

	"github.com/sundi133/nexus-agent/internal/platform"
	"github.com/sundi133/nexus-agent/internal/policy"
)

// EnrollRequest registers a new device with the cloud.
type EnrollRequest struct {
	EnrollmentToken string              `json:"enrollment_token"`
	HardwareID      string              `json:"hardware_id"`
	Device          platform.DeviceInfo `json:"device"`
	AgentVersion    string              `json:"agent_version"`
}

// EnrollResponse is returned once enrollment succeeds.
type EnrollResponse struct {
	DeviceID   string `json:"device_id"`
	AgentToken string `json:"agent_token"`
	OrgID      string `json:"org_id"`
}

// HeartbeatRequest is a lightweight liveness ping.
type HeartbeatRequest struct {
	AgentVersion  string    `json:"agent_version"`
	Timestamp     time.Time `json:"timestamp"`
	Uptime        int64     `json:"uptime_seconds"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	ConsoleUser   string    `json:"console_user,omitempty"`
}

// HeartbeatResponse lets the cloud nudge the agent.
type HeartbeatResponse struct {
	// PolicyVersion is the latest policy version; the agent refreshes if it differs.
	PolicyVersion string `json:"policy_version,omitempty"`
	// PendingCommands tells the agent to poll commands immediately.
	PendingCommands bool `json:"pending_commands,omitempty"`
}

// Event is one normalized telemetry record.
type Event struct {
	DeviceID  string          `json:"device_id"`
	Timestamp time.Time       `json:"timestamp"`
	Type      string          `json:"type"`
	Source    string          `json:"source"` // "platform", "osquery", "detector"
	Data      json.RawMessage `json:"data"`
}

// Telemetry event types.
const (
	EventDeviceInfo     = "device_info"
	EventPosture        = "security_posture"
	EventProcesses      = "process_inventory"
	EventConnections    = "network_connections"
	EventApplications   = "application_inventory"
	EventAIAgents       = "ai_agent_inventory"
	EventAIAgentGraph   = "ai_agent_graph"
	EventPolicyDecision = "policy_decision"
	EventOsqueryResult  = "osquery_result"
)

// TelemetryBatch is posted to the telemetry endpoint.
type TelemetryBatch struct {
	Events []Event `json:"events"`
}

// PolicyResponse carries the policy bundle for this device.
type PolicyResponse = policy.Bundle

// Command is an instruction from the cloud. Commands are drawn from a fixed
// allow-list; the agent never executes arbitrary shell from the cloud.
type Command struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Args      json.RawMessage `json:"args,omitempty"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at,omitempty"`
}

// Supported command types.
const (
	CmdCollectTelemetry = "collect_telemetry"
	CmdRefreshPolicy    = "refresh_policy"
	CmdOsqueryQuery     = "osquery_query" // read-only SELECT
	CmdCheckUpdate      = "check_update"
	CmdLockScreen       = "lock_screen"
	CmdNotifyUser       = "notify_user"
)

// CommandResult reports the outcome of a command.
type CommandResult struct {
	Status   string          `json:"status"` // "ok" | "error" | "rejected"
	Output   json.RawMessage `json:"output,omitempty"`
	Error    string          `json:"error,omitempty"`
	Finished time.Time       `json:"finished_at"`
}

// UpdateInfo describes an available agent release.
type UpdateInfo struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	URL       string `json:"url,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	// Signature is base64 ed25519 over the raw 32-byte SHA-256 digest.
	Signature string `json:"signature,omitempty"`
}
