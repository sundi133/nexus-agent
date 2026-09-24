//go:build !darwin && !windows && !linux

package platform

import (
	"context"
	"os"
	"runtime"
)

// genericPlatform keeps the core compiling on unsupported targets
// (e.g. FreeBSD). It reports only what the Go runtime knows.
type genericPlatform struct{}

func newPlatform() Platform { return genericPlatform{} }

func (genericPlatform) OS() string { return runtime.GOOS }
func (genericPlatform) DeviceInfo(context.Context) (DeviceInfo, error) {
	h, _ := os.Hostname()
	return DeviceInfo{Hostname: h, OS: runtime.GOOS, Arch: runtime.GOARCH}, nil
}
func (genericPlatform) HardwareID(context.Context) (string, error) { return "", ErrNotSupported }
func (genericPlatform) ConsoleUser(context.Context) string         { return "" }
func (genericPlatform) UserHomeDirs() []string                     { return nil }
func (genericPlatform) Processes(context.Context) ([]Process, error) {
	return nil, ErrNotSupported
}
func (genericPlatform) NetworkConnections(context.Context) ([]Connection, error) {
	return nil, ErrNotSupported
}
func (genericPlatform) InstalledApps(context.Context) ([]Application, error) {
	return nil, ErrNotSupported
}
func (genericPlatform) SecurityPosture(context.Context) (*Posture, error) {
	return nil, ErrNotSupported
}
func (genericPlatform) LockScreen(context.Context) error             { return ErrNotSupported }
func (genericPlatform) Notify(context.Context, string, string) error { return ErrNotSupported }
