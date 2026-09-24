// Package service adapts the agent to each OS service manager:
//
//	macOS   launchd  (LaunchDaemon, SIGTERM on stop)
//	Linux   systemd  (SIGTERM on stop)
//	Windows SCM      (service control protocol via x/sys/windows/svc)
package service

import "context"

// Name is the service identifier used by all service managers.
const Name = "VotalAgent"

// RunFunc is the agent main loop. It must return when ctx is cancelled.
type RunFunc func(ctx context.Context) error

// Run executes fn under the platform service manager if the process was
// started by one, otherwise in the foreground with signal handling.
func Run(fn RunFunc) error { return run(fn) }

// IsService reports whether the process was started by the Windows SCM.
// Always false on Unix, where launchd/systemd just run a foreground process.
func IsService() bool { return isService() }
