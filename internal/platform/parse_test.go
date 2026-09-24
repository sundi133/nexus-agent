package platform

import (
	"reflect"
	"testing"
)

func TestParsePS(t *testing.T) {
	out := `    1     0 root             /sbin/launchd
  512     1 alice            /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  777   512 alice            Cursor
garbage line
`
	got := parsePS(out)
	want := []Process{
		{PID: 1, PPID: 0, User: "root", Name: "launchd", Path: "/sbin/launchd"},
		{PID: 512, PPID: 1, User: "alice", Name: "Google Chrome", Path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
		{PID: 777, PPID: 512, User: "alice", Name: "Cursor"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePS:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseLsofF(t *testing.T) {
	out := "p812\ncCursor\nf23\nPTCP\nn192.168.1.5:50514->34.1.2.3:443\nTST=ESTABLISHED\nTQR=0\nf24\nPTCP\nn*:7777\nTST=LISTEN\np900\ncollama\nf5\nPTCP\nn[::1]:11434\nTST=LISTEN\nf6\nPUDP\nn*:5353\n"
	got := parseLsofF(out)
	want := []Connection{
		{Protocol: "tcp", LocalAddr: "192.168.1.5", LocalPort: 50514, RemoteAddr: "34.1.2.3", RemotePort: 443, State: "ESTABLISHED", PID: 812, Process: "Cursor"},
		{Protocol: "tcp", LocalAddr: "*", LocalPort: 7777, State: "LISTEN", PID: 812, Process: "Cursor"},
		{Protocol: "tcp6", LocalAddr: "::1", LocalPort: 11434, State: "LISTEN", PID: 900, Process: "ollama"},
		{Protocol: "udp", LocalAddr: "*", LocalPort: 5353, PID: 900, Process: "ollama"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseLsofF:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41234 1 0000000000000000 100 0 0 10 0
   1: 0501A8C0:C5D2 03020122:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 41299 1 0000000000000000 20 4 30 10 -1
`
	got := parseProcNet(tcp, "tcp")
	if len(got) != 2 {
		t.Fatalf("want 2 sockets, got %d", len(got))
	}
	if c := got[0].Conn; c.LocalAddr != "127.0.0.1" || c.LocalPort != 11434 || c.State != "LISTEN" || c.RemoteAddr != "" || got[0].Inode != "41234" {
		t.Errorf("listen socket: %+v", got[0])
	}
	if c := got[1].Conn; c.LocalAddr != "192.168.1.5" || c.RemoteAddr != "34.1.2.3" || c.RemotePort != 443 || c.State != "ESTABLISHED" {
		t.Errorf("established socket: %+v", c)
	}

	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 100 0 0 10 0
`
	got6 := parseProcNet(tcp6, "tcp6")
	if len(got6) != 1 || got6[0].Conn.LocalAddr != "::1" || got6[0].Conn.LocalPort != 8080 {
		t.Fatalf("tcp6: %+v", got6)
	}
}

func TestParseWindowsNetstat(t *testing.T) {
	out := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044
  TCP    10.0.0.4:52100         52.1.2.3:443           ESTABLISHED     7312
  TCP    [::1]:11434            [::]:0                 LISTENING       9001
  UDP    0.0.0.0:5353           *:*                                    2220
`
	got := parseWindowsNetstat(out)
	want := []Connection{
		{Protocol: "tcp", LocalAddr: "0.0.0.0", LocalPort: 135, State: "LISTEN", PID: 1044},
		{Protocol: "tcp", LocalAddr: "10.0.0.4", LocalPort: 52100, RemoteAddr: "52.1.2.3", RemotePort: 443, State: "ESTABLISHED", PID: 7312},
		{Protocol: "tcp6", LocalAddr: "::1", LocalPort: 11434, State: "LISTEN", PID: 9001},
		{Protocol: "udp", LocalAddr: "0.0.0.0", LocalPort: 5353, PID: 2220},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseWindowsNetstat:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseNetshFirewall(t *testing.T) {
	out := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Ok.
`
	on, total := parseNetshFirewall(out)
	if on != 2 || total != 3 {
		t.Fatalf("got %d/%d, want 2/3", on, total)
	}
}

func TestParseOSReleaseAndPackages(t *testing.T) {
	rel := parseOSRelease("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n# comment\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n")
	if rel["PRETTY_NAME"] != "Ubuntu 24.04 LTS" || rel["VERSION_ID"] != "24.04" {
		t.Fatalf("os-release: %v", rel)
	}
	apps := parseTabbedPackages("curl\t8.5.0\nbad-line\nollama\t0.3.1\n", "dpkg")
	if len(apps) != 2 || apps[1].Name != "ollama" || apps[1].Version != "0.3.1" || apps[1].Source != "dpkg" {
		t.Fatalf("packages: %+v", apps)
	}
}

func TestNewPlatformCompiles(t *testing.T) {
	p := New()
	if p.OS() == "" {
		t.Fatal("empty OS")
	}
}
