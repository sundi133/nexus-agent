package platform

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// parsePS parses `ps -axo pid=,ppid=,user=,comm=` output (macOS/BSD).
// comm may contain spaces (e.g. "/Applications/Google Chrome.app/..."),
// so everything after the third field is the path.
func parsePS(out string) []Process {
	var procs []Process
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		// Re-join the remainder to preserve spaces in the path.
		line := strings.TrimSpace(sc.Text())
		rest := line
		for i := 0; i < 3; i++ {
			rest = strings.TrimLeft(rest, " \t")
			if j := strings.IndexAny(rest, " \t"); j >= 0 {
				rest = rest[j:]
			}
		}
		path := strings.TrimSpace(rest)
		p := Process{PID: pid, PPID: ppid, User: f[2], Name: filepath.Base(path)}
		if strings.HasPrefix(path, "/") {
			p.Path = path
		}
		procs = append(procs, p)
	}
	return procs
}

// splitHostPort splits "1.2.3.4:443", "[::1]:443", "*:53" or "*:*".
func splitHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	host := strings.Trim(s[:i], "[]")
	port, _ := strconv.Atoi(s[i+1:])
	return host, port
}

// parseLsofF parses `lsof -nP -iTCP -iUDP -FpcPnT` field output.
func parseLsofF(out string) []Connection {
	var (
		conns   []Connection
		pid     int
		command string
		cur     *Connection
	)
	flush := func() {
		if cur != nil {
			conns = append(conns, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			flush()
			pid, _ = strconv.Atoi(val)
			command = ""
		case 'c':
			command = val
		case 'f':
			flush()
			cur = &Connection{PID: pid, Process: command}
		case 'P':
			if cur != nil {
				cur.Protocol = strings.ToLower(val)
			}
		case 'n':
			if cur == nil {
				continue
			}
			local, remote, _ := strings.Cut(val, "->")
			cur.LocalAddr, cur.LocalPort = splitHostPort(local)
			if remote != "" {
				cur.RemoteAddr, cur.RemotePort = splitHostPort(remote)
			}
			if strings.Contains(local, "[") && !strings.HasSuffix(cur.Protocol, "6") {
				cur.Protocol += "6"
			}
		case 'T':
			if cur != nil && strings.HasPrefix(val, "ST=") {
				cur.State = strings.TrimPrefix(val, "ST=")
			}
		}
	}
	flush()
	// Drop entries that never received a protocol (non-network fds).
	res := conns[:0]
	for _, c := range conns {
		if c.Protocol != "" {
			res = append(res, c)
		}
	}
	return res
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// procSocket is one row of /proc/net/{tcp,tcp6,udp,udp6}.
type procSocket struct {
	Conn  Connection
	Inode string
}

// parseProcNet parses a /proc/net/{tcp,udp}[6] table.
func parseProcNet(content, proto string) []procSocket {
	var out []procSocket
	lines := strings.Split(content, "\n")
	for _, line := range lines[min(1, len(lines)):] { // skip header
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		la, lp, ok1 := decodeProcAddr(f[1])
		ra, rp, ok2 := decodeProcAddr(f[2])
		if !ok1 || !ok2 {
			continue
		}
		c := Connection{Protocol: proto, LocalAddr: la, LocalPort: lp}
		if rp != 0 {
			c.RemoteAddr, c.RemotePort = ra, rp
		}
		if strings.HasPrefix(proto, "tcp") {
			c.State = tcpStates[strings.ToUpper(f[3])]
		}
		out = append(out, procSocket{Conn: c, Inode: f[9]})
	}
	return out
}

// decodeProcAddr decodes "0100007F:1F90" (IPv4) or a 32-hex-char IPv6 addr.
// The kernel prints each 32-bit word in host (little-endian) order.
func decodeProcAddr(s string) (string, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	return ip.String(), int(port), true
}

// parseWindowsNetstat parses `netstat -ano` output.
func parseWindowsNetstat(out string) []Connection {
	var conns []Connection
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		c := Connection{Protocol: proto}
		c.LocalAddr, c.LocalPort = splitHostPort(f[1])
		if f[2] != "*:*" {
			c.RemoteAddr, c.RemotePort = splitHostPort(f[2])
			if c.RemotePort == 0 {
				c.RemoteAddr = ""
			}
		}
		pidField := f[len(f)-1]
		if proto == "tcp" && len(f) >= 5 {
			c.State = normalizeWinState(f[3])
		}
		c.PID, _ = strconv.Atoi(pidField)
		if strings.Contains(f[1], "[") {
			c.Protocol += "6"
		}
		conns = append(conns, c)
	}
	return conns
}

func normalizeWinState(s string) string {
	switch strings.ToUpper(s) {
	case "LISTENING":
		return "LISTEN"
	default:
		return strings.ToUpper(s)
	}
}

// parseOSRelease parses /etc/os-release KEY=value lines.
func parseOSRelease(content string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		m[k] = strings.Trim(v, `"'`)
	}
	return m
}

// parseTabbedPackages parses "name\tversion" lines from dpkg-query/rpm.
func parseTabbedPackages(out, source string) []Application {
	var apps []Application
	for _, line := range strings.Split(out, "\n") {
		name, ver, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" {
			continue
		}
		apps = append(apps, Application{Name: name, Version: ver, Source: source})
	}
	return apps
}

// listHomeDirs returns subdirectories of root, excluding names in skip.
func listHomeDirs(root string, skip ...string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[strings.ToLower(s)] = true
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || skipSet[strings.ToLower(e.Name())] {
			continue
		}
		dirs = append(dirs, filepath.Join(root, e.Name()))
	}
	sort.Strings(dirs)
	return dirs
}

// attachProcessNames fills Connection.Process from a PID map.
func attachProcessNames(conns []Connection, procs []Process) {
	names := make(map[int]string, len(procs))
	for _, p := range procs {
		names[p.PID] = p.Name
	}
	for i := range conns {
		if conns[i].Process == "" && conns[i].PID != 0 {
			conns[i].Process = names[conns[i].PID]
		}
	}
}

// parseNetshFirewall counts profiles reporting "State ON" in
// `netsh advfirewall show allprofiles state` output.
func parseNetshFirewall(out string) (on, total int) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.EqualFold(f[0], "State") {
			total++
			if strings.EqualFold(f[1], "ON") {
				on++
			}
		}
	}
	return on, total
}
