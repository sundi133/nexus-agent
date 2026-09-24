//go:build darwin

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DarwinPlatform implements Platform using macOS system utilities.
type DarwinPlatform struct{}

func newPlatform() Platform { return &DarwinPlatform{} }

func (p *DarwinPlatform) OS() string { return "macos" }

func (p *DarwinPlatform) DeviceInfo(ctx context.Context) (DeviceInfo, error) {
	host, _ := os.Hostname()
	info := DeviceInfo{Hostname: host, OS: p.OS(), Arch: runtime.GOARCH, ConsoleUser: p.ConsoleUser(ctx)}
	info.OSVersion, _ = run(ctx, "sw_vers", "-productVersion")
	info.Kernel, _ = run(ctx, "uname", "-r")
	info.Model, _ = run(ctx, "sysctl", "-n", "hw.model")
	if out, err := run(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		info.SerialNumber = ioregValue(out, "IOPlatformSerialNumber")
	}
	return info, nil
}

func (p *DarwinPlatform) HardwareID(ctx context.Context) (string, error) {
	out, err := run(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", err
	}
	if id := ioregValue(out, "IOPlatformUUID"); id != "" {
		return id, nil
	}
	return "", errors.New("IOPlatformUUID not found")
}

// ioregValue extracts `"Key" = "value"` from ioreg output.
func ioregValue(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.Trim(strings.TrimSpace(k), `"`) == key {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func (p *DarwinPlatform) ConsoleUser(ctx context.Context) string {
	u, err := run(ctx, "stat", "-f", "%Su", "/dev/console")
	if err != nil || u == "root" || u == "_mbsetupuser" {
		return ""
	}
	return u
}

func (p *DarwinPlatform) UserHomeDirs() []string {
	return listHomeDirs("/Users", "Shared", "Guest")
}

func (p *DarwinPlatform) Processes(ctx context.Context) ([]Process, error) {
	out, err := run(ctx, "ps", "-axo", "pid=,ppid=,user=,comm=")
	if err != nil {
		return nil, err
	}
	return parsePS(out), nil
}

func (p *DarwinPlatform) NetworkConnections(ctx context.Context) ([]Connection, error) {
	// lsof exits 1 when some fds could not be inspected; keep partial output.
	out, err := run(ctx, "lsof", "-nP", "-iTCP", "-iUDP", "-FpcPnT")
	if out == "" && err != nil {
		return nil, err
	}
	return parseLsofF(out), nil
}

func (p *DarwinPlatform) InstalledApps(ctx context.Context) ([]Application, error) {
	roots := []string{"/Applications", "/Applications/Utilities", "/System/Applications"}
	for _, home := range p.UserHomeDirs() {
		roots = append(roots, filepath.Join(home, "Applications"))
	}
	var apps []Application
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			path := filepath.Join(root, e.Name())
			app := Application{Name: strings.TrimSuffix(e.Name(), ".app"), Path: path, Source: "applications_dir"}
			if meta, err := readInfoPlist(ctx, filepath.Join(path, "Contents", "Info.plist")); err == nil {
				if meta.Name != "" {
					app.Name = meta.Name
				}
				app.Version = meta.Version
				app.BundleID = meta.BundleID
			}
			apps = append(apps, app)
		}
	}
	return apps, nil
}

type bundleMeta struct {
	Name     string `json:"CFBundleName"`
	Version  string `json:"CFBundleShortVersionString"`
	BundleID string `json:"CFBundleIdentifier"`
}

// readInfoPlist converts (binary or XML) plists via plutil.
func readInfoPlist(ctx context.Context, path string) (bundleMeta, error) {
	var m bundleMeta
	out, err := run(ctx, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal([]byte(out), &m)
	return m, err
}

func (p *DarwinPlatform) SecurityPosture(ctx context.Context) (*Posture, error) {
	checks := []PostureCheck{}

	out, err := run(ctx, "fdesetup", "status")
	checks = append(checks, boolCheck(CheckDiskEncryption, strings.Contains(out, "FileVault is On"), err, "FileVault: "+out))

	out, err = run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	checks = append(checks, boolCheck(CheckFirewall, strings.Contains(strings.ToLower(out), "enabled"), err, out))

	out, err = run(ctx, "csrutil", "status")
	checks = append(checks, boolCheck(CheckOSProtection, strings.Contains(out, "enabled"), err, "SIP: "+out))

	out, err = run(ctx, "spctl", "--status")
	checks = append(checks, boolCheck(CheckAppControl, strings.Contains(out, "assessments enabled"), err, "Gatekeeper: "+out))

	// XProtect is always present on supported macOS versions.
	_, statErr := os.Stat("/Library/Apple/System/Library/CoreServices/XProtect.bundle")
	checks = append(checks, boolCheck(CheckAntivirus, statErr == nil, nil, "XProtect"))

	return &Posture{CollectedAt: time.Now().UTC(), Checks: checks}, nil
}

func (p *DarwinPlatform) LockScreen(ctx context.Context) error {
	// Sleeping the display locks the session when "require password" is set
	// (enforced by MDM in managed fleets).
	_, err := run(ctx, "pmset", "displaysleepnow")
	return err
}

func (p *DarwinPlatform) Notify(ctx context.Context, title, message string) error {
	uid, err := run(ctx, "stat", "-f", "%u", "/dev/console")
	if err != nil || uid == "0" {
		return errors.New("no console user")
	}
	script := "display notification " + appleScriptString(message) + " with title " + appleScriptString(title)
	// Run inside the console user's GUI session.
	_, err = run(ctx, "launchctl", "asuser", uid, "osascript", "-e", script)
	return err
}

// appleScriptString quotes s as an AppleScript string literal.
func appleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
