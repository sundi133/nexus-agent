// Package version holds build metadata injected via -ldflags.
package version

import "runtime"

var (
	// Version is the semantic version of the agent, e.g. "0.1.0".
	Version = "0.0.0-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// BuildDate is the RFC3339 build timestamp.
	BuildDate = "unknown"
)

// Platform returns "<os>/<arch>" for the running binary.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// String returns a human-readable version line.
func String() string {
	return "votal-agent " + Version + " (" + Commit + ", " + BuildDate + ", " + Platform() + ")"
}
