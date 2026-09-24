//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// LinuxPlatform implements Platform using /proc and standard distro tools.
type LinuxPlatform struct {
	procRoot string
}

func newPlatform() Platform { return &LinuxPlatform{procRoot: "/proc"} }

func (p *LinuxPlatform) OS() string { return "linux" }

func (p *LinuxPlatform) DeviceInfo(ctx context.Context) (DeviceInfo, error) {
	host, _ := os.Hostname()
	info := DeviceInfo{Hostname: host, OS: p.OS(), Arch: runtime.GOARCH, ConsoleUser: p.ConsoleUser(ctx)}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		rel := parseOSRelease(string(b))
		info.OSVersion = rel["PRETTY_NAME"]
		if info.OSVersion == "" {
			info.OSVersion = strings.TrimSpace(rel["NAME"] + " " + rel["VERSION_ID"])
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	info.Model = readTrim("/sys/class/dmi/id/product_name")
	info.SerialNumber = readTrim("/sys/class/dmi/id/product_serial") // root-only; empty otherwise
	return info, nil
}

func (p *LinuxPlatform) HardwareID(ctx context.Context) (string, error) {
	for _, f := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"} {
		if v := readTrim(f); v != "" {
			return v, nil
		}
	}
	return "", errors.New("no machine-id found")
}

func (p *LinuxPlatform) ConsoleUser(ctx context.Context) string {
	// Prefer a logind session that is attached to a seat (i.e. physical/graphical).
	if out, err := run(ctx, "loginctl", "list-sessions", "--no-legend"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			// SESSION UID USER SEAT ...
			if len(f) >= 4 && strings.HasPrefix(f[3], "seat") {
				return f[2]
			}
		}
	}
	if out, err := run(ctx, "who"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && (strings.HasPrefix(f[1], ":") || strings.HasPrefix(f[1], "tty")) {
				return f[0]
			}
		}
	}
	return ""
}

func (p *LinuxPlatform) UserHomeDirs() []string {
	dirs := listHomeDirs("/home", "lost+found")
	if _, err := os.Stat("/root"); err == nil {
		dirs = append(dirs, "/root")
	}
	return dirs
}

func (p *LinuxPlatform) Processes(ctx context.Context) ([]Process, error) {
	entries, err := os.ReadDir(p.procRoot)
	if err != nil {
		return nil, err
	}
	users := map[string]string{}
	var procs []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(p.procRoot, e.Name())
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue // process exited
		}
		name, ppid := parseProcStat(string(stat))
		proc := Process{PID: pid, PPID: ppid, Name: name}
		if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
			proc.Path = strings.TrimSuffix(exe, " (deleted)")
			proc.Name = filepath.Base(proc.Path)
		}
		if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
			if uid := statusField(string(st), "Uid:"); uid != "" {
				proc.User = lookupUser(users, uid)
			}
		}
		procs = append(procs, proc)
	}
	return procs, nil
}

// parseProcStat extracts comm and ppid from /proc/<pid>/stat. comm is
// wrapped in parentheses and may itself contain spaces or parens.
func parseProcStat(s string) (string, int) {
	open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || close < open {
		return "", 0
	}
	name := s[open+1 : close]
	rest := strings.Fields(s[close+1:])
	if len(rest) < 2 {
		return name, 0
	}
	ppid, _ := strconv.Atoi(rest[1])
	return name, ppid
}

func statusField(status, key string) string {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, key) {
			f := strings.Fields(strings.TrimPrefix(line, key))
			if len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

func lookupUser(cache map[string]string, uid string) string {
	if n, ok := cache[uid]; ok {
		return n
	}
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	cache[uid] = name
	return name
}

func (p *LinuxPlatform) NetworkConnections(ctx context.Context) ([]Connection, error) {
	var sockets []procSocket
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(filepath.Join(p.procRoot, "net", proto))
		if err != nil {
			continue
		}
		sockets = append(sockets, parseProcNet(string(b), proto)...)
	}
	owners := p.socketOwners()
	procs, _ := p.Processes(ctx)
	conns := make([]Connection, 0, len(sockets))
	for _, s := range sockets {
		c := s.Conn
		c.PID = owners[s.Inode]
		conns = append(conns, c)
	}
	attachProcessNames(conns, procs)
	return conns, nil
}

// socketOwners maps socket inode -> pid by walking /proc/<pid>/fd.
func (p *LinuxPlatform) socketOwners() map[string]int {
	owners := map[string]int{}
	entries, _ := os.ReadDir(p.procRoot)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(p.procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				owners[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = pid
			}
		}
	}
	return owners
}

func (p *LinuxPlatform) InstalledApps(ctx context.Context) ([]Application, error) {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := run(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
		if err == nil {
			return parseTabbedPackages(out, "dpkg"), nil
		}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := run(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
		if err == nil {
			return parseTabbedPackages(out, "rpm"), nil
		}
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		out, err := run(ctx, "pacman", "-Q")
		if err == nil {
			return parseTabbedPackages(strings.ReplaceAll(out, " ", "\t"), "pacman"), nil
		}
	}
	return nil, errors.New("no supported package manager found")
}

func (p *LinuxPlatform) SecurityPosture(ctx context.Context) (*Posture, error) {
	return &Posture{
		CollectedAt: time.Now().UTC(),
		Checks: []PostureCheck{
			p.diskEncryption(ctx),
			p.firewall(ctx),
			p.mandatoryAccessControl(),
		},
	}, nil
}

func (p *LinuxPlatform) diskEncryption(ctx context.Context) PostureCheck {
	out, err := run(ctx, "lsblk", "-n", "-o", "TYPE,MOUNTPOINT")
	if err != nil {
		return boolCheck(CheckDiskEncryption, false, err, "")
	}
	// Root filesystem sits on a dm-crypt device if any "crypt" layer mounts "/".
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "crypt" && f[1] == "/" {
			return boolCheck(CheckDiskEncryption, true, nil, "root on dm-crypt")
		}
	}
	hasCrypt := strings.Contains(out, "crypt")
	detail := "no dm-crypt device for /"
	if hasCrypt {
		// LVM-on-LUKS: crypt device exists and "/" is an lvm volume above it.
		detail = "dm-crypt device present"
	}
	return boolCheck(CheckDiskEncryption, hasCrypt, nil, detail)
}

func (p *LinuxPlatform) firewall(ctx context.Context) PostureCheck {
	if out, err := run(ctx, "ufw", "status"); err == nil {
		return boolCheck(CheckFirewall, strings.Contains(out, "Status: active"), nil, "ufw")
	}
	if out, err := run(ctx, "firewall-cmd", "--state"); err == nil || out != "" {
		return boolCheck(CheckFirewall, strings.TrimSpace(out) == "running", nil, "firewalld")
	}
	if out, err := run(ctx, "nft", "list", "ruleset"); err == nil {
		return boolCheck(CheckFirewall, strings.Contains(out, "chain"), nil, "nftables")
	}
	return boolCheck(CheckFirewall, false, errors.New("no firewall tool found"), "")
}

func (p *LinuxPlatform) mandatoryAccessControl() PostureCheck {
	if readTrim("/sys/fs/selinux/enforce") == "1" {
		return boolCheck(CheckOSProtection, true, nil, "SELinux enforcing")
	}
	if readTrim("/sys/module/apparmor/parameters/enabled") == "Y" {
		return boolCheck(CheckOSProtection, true, nil, "AppArmor enabled")
	}
	return boolCheck(CheckOSProtection, false, nil, "no SELinux/AppArmor enforcement")
}

func (p *LinuxPlatform) LockScreen(ctx context.Context) error {
	_, err := run(ctx, "loginctl", "lock-sessions")
	return err
}

func (p *LinuxPlatform) Notify(ctx context.Context, title, message string) error {
	// wall reaches every terminal; desktop notifications need the user's
	// session bus, which a system service does not own.
	_, err := run(ctx, "wall", fmt.Sprintf("[%s] %s", title, message))
	return err
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
