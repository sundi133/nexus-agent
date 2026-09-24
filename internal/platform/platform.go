// Package platform abstracts every OS-specific operation the agent needs.
//
// The shared agent core only talks to the Platform interface. Each supported
// OS provides an implementation behind a build tag (darwin.go, windows.go,
// linux.go); unsupported targets get a stub (other.go) so the core still
// compiles everywhere.
//
// Output parsers for OS tools live in untagged files (parse.go) so they can be
// unit-tested on any build host.
package platform

import (
	"context"
	"errors"
	"time"
)

// ErrNotSupported is returned for operations unavailable on this OS.
var ErrNotSupported = errors.New("not supported on this platform")

// Platform is the contract every OS module implements.
type Platform interface {
	// OS returns "macos", "windows", or "linux".
	OS() string
	// DeviceInfo returns static-ish facts about the machine.
	DeviceInfo(ctx context.Context) (DeviceInfo, error)
	// HardwareID returns a stable per-machine identifier used during enrollment.
	HardwareID(ctx context.Context) (string, error)
	// ConsoleUser returns the user logged in at the physical console, if any.
	ConsoleUser(ctx context.Context) string
	// UserHomeDirs lists home directories of local human users. The agent
	// runs as root/SYSTEM, so per-user config (e.g. MCP configs) is found here.
	UserHomeDirs() []string

	Processes(ctx context.Context) ([]Process, error)
	NetworkConnections(ctx context.Context) ([]Connection, error)
	InstalledApps(ctx context.Context) ([]Application, error)
	SecurityPosture(ctx context.Context) (*Posture, error)

	// LockScreen locks the interactive session (response action).
	LockScreen(ctx context.Context) error
	// Notify shows a message to the console user.
	Notify(ctx context.Context, title, message string) error
}

// DeviceInfo describes the host.
type DeviceInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	ConsoleUser  string `json:"console_user,omitempty"`
}

// Process is a running process. Command lines are deliberately excluded
// because they frequently contain credentials.
type Process struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	User string `json:"user,omitempty"`
}

// Connection is a socket owned by a process.
type Connection struct {
	Protocol   string `json:"protocol"` // tcp, tcp6, udp, udp6
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
	PID        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
}

// Application is an installed application or package.
type Application struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	BundleID  string `json:"bundle_id,omitempty"`
	Source    string `json:"source"` // e.g. "applications_dir", "registry", "dpkg", "rpm"
}

// CheckStatus is the outcome of a posture check.
type CheckStatus string

const (
	StatusPass    CheckStatus = "pass"
	StatusFail    CheckStatus = "fail"
	StatusUnknown CheckStatus = "unknown"
)

// PostureCheck is one security control evaluation.
type PostureCheck struct {
	ID     string      `json:"id"` // e.g. "disk_encryption", "firewall"
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
}

// Posture is the device's security posture snapshot.
type Posture struct {
	CollectedAt time.Time      `json:"collected_at"`
	Checks      []PostureCheck `json:"checks"`
}

// Check returns the check with the given ID, or StatusUnknown.
func (p *Posture) Check(id string) PostureCheck {
	for _, c := range p.Checks {
		if c.ID == id {
			return c
		}
	}
	return PostureCheck{ID: id, Status: StatusUnknown}
}

// Standard posture check IDs shared across platforms so the cloud can
// compare devices uniformly.
const (
	CheckDiskEncryption = "disk_encryption"
	CheckFirewall       = "firewall"
	CheckAntivirus      = "antivirus"
	CheckOSProtection   = "os_protection" // SIP / UAC / SELinux-AppArmor
	CheckAppControl     = "app_control"   // Gatekeeper / SmartScreen
)

// New returns the Platform for the running OS.
func New() Platform { return newPlatform() }
