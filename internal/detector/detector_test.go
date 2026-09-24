package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sundi133/nexus-agent/internal/platform"
)

type fakeFS map[string]string

func (f fakeFS) ReadFile(p string) ([]byte, error) {
	if v, ok := f[filepath.ToSlash(p)]; ok {
		return []byte(v), nil
	}
	return nil, os.ErrNotExist
}

func (f fakeFS) Glob(pattern string) ([]string, error) {
	var out []string
	for k := range f {
		if ok, _ := filepath.Match(filepath.ToSlash(pattern), k); ok {
			out = append(out, k)
		}
	}
	return out, nil
}

func newTestDetector(fs fakeFS) *Detector {
	d := New(BuiltinRegistry())
	d.fs = fs
	return d
}

func find(agents []DetectedAgent, id string) *DetectedAgent {
	for i := range agents {
		if agents[i].ID == id {
			return &agents[i]
		}
	}
	return nil
}

func TestBuiltinRegistryIsValid(t *testing.T) {
	r := BuiltinRegistry()
	seen := map[string]bool{}
	for _, a := range r.Agents {
		if seen[a.ID] {
			t.Errorf("duplicate id %s", a.ID)
		}
		seen[a.ID] = true
		switch a.Category {
		case CategoryAssistant, CategoryCodingAgent, CategoryMCPClient, CategoryLocalLLM:
		default:
			t.Errorf("%s: unknown category %q", a.ID, a.Category)
		}
	}
}

func TestDetectCursorWithMCPAndSecretsRedacted(t *testing.T) {
	fs := fakeFS{
		"/Users/alice/.cursor/mcp.json": `{
		  "mcpServers": {
		    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
		               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
		    "prod-db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres",
		               "postgresql://admin:hunter2@db.internal:5432/prod"]},
		    "remote": {"url": "https://mcp.example.com/sse?api_key=sk-live-secret&team=x"},
		    "tool": {"command": "mytool", "args": ["--api-key", "abc123", "--verbose", "--token=xyz"]}
		  }
		}`,
	}
	snap := Snapshot{
		OS:        "macos",
		HomeDirs:  []string{"/Users/alice"},
		Processes: []platform.Process{{PID: 42, Name: "Cursor", User: "alice"}},
		Apps:      []platform.Application{{Name: "Cursor", Version: "1.2.0", Path: "/Applications/Cursor.app"}},
	}
	got := newTestDetector(fs).Detect(snap)
	c := find(got, "cursor")
	if c == nil {
		t.Fatalf("cursor not detected: %+v", got)
	}
	if !c.Running || !c.Installed || c.Version != "1.2.0" || len(c.PIDs) != 1 {
		t.Errorf("cursor state: %+v", c)
	}
	if len(c.MCPServers) != 4 {
		t.Fatalf("want 4 MCP servers, got %d", len(c.MCPServers))
	}

	byName := map[string]MCPServer{}
	for _, s := range c.MCPServers {
		byName[s.Name] = s
	}
	gh := byName["github"]
	if gh.Transport != "stdio" || strings.Join(gh.ResourceHints, ",") != "github" || gh.User != "alice" {
		t.Errorf("github server: %+v", gh)
	}
	if len(gh.EnvKeys) != 1 || gh.EnvKeys[0] != "GITHUB_PERSONAL_ACCESS_TOKEN" {
		t.Errorf("env keys: %v", gh.EnvKeys)
	}
	db := byName["prod-db"]
	if strings.Contains(strings.Join(db.Args, " "), "hunter2") {
		t.Errorf("postgres password leaked: %v", db.Args)
	}
	if strings.Join(db.ResourceHints, ",") != "database:postgres" {
		t.Errorf("db hints: %v", db.ResourceHints)
	}
	remote := byName["remote"]
	if remote.Transport != "sse" || strings.Contains(remote.URL, "sk-live-secret") || !strings.Contains(remote.URL, "team=x") {
		t.Errorf("remote: %+v", remote)
	}
	tool := byName["tool"]
	want := []string{"--api-key", redacted, "--verbose", "--token=" + redacted}
	if strings.Join(tool.Args, " ") != strings.Join(want, " ") {
		t.Errorf("args redaction: got %v want %v", tool.Args, want)
	}

	// Nothing secret anywhere in the serialized detection.
	for _, s := range c.MCPServers {
		all := strings.Join(append(append([]string{s.URL}, s.Args...), s.EnvKeys...), " ")
		for _, secret := range []string{"ghp_abc", "hunter2", "sk-live", "abc123", "xyz"} {
			if strings.Contains(all, secret) {
				t.Errorf("secret %q leaked in %s: %s", secret, s.Name, all)
			}
		}
	}
}

func TestProcessMatchingIsCaseSensitive(t *testing.T) {
	// "claude" is Claude Code; "Claude" is Claude Desktop.
	snap := Snapshot{OS: "linux", Processes: []platform.Process{{PID: 7, Name: "claude"}}}
	got := newTestDetector(fakeFS{}).Detect(snap)
	if find(got, "claude_code") == nil {
		t.Error("claude_code not detected")
	}
	if find(got, "claude_desktop") != nil {
		t.Error("claude_desktop falsely detected from CLI process")
	}
	// Windows ".exe" suffix is stripped.
	got = newTestDetector(fakeFS{}).Detect(Snapshot{OS: "windows", Processes: []platform.Process{{PID: 8, Name: "Claude.exe"}}})
	if find(got, "claude_desktop") == nil {
		t.Error("Claude.exe not detected as desktop")
	}
}

func TestPortRequiresOwningProcess(t *testing.T) {
	snap := Snapshot{OS: "linux", Connections: []platform.Connection{
		{Protocol: "tcp", LocalPort: 8080, State: "LISTEN", Process: "nginx"},
		{Protocol: "tcp", LocalPort: 11434, State: "LISTEN"}, // unknown owner
	}}
	if got := newTestDetector(fakeFS{}).Detect(snap); len(got) != 0 {
		t.Fatalf("ports without matching owner must not detect: %+v", got)
	}
	snap.Connections = append(snap.Connections, platform.Connection{Protocol: "tcp", LocalPort: 11434, State: "LISTEN", Process: "ollama"})
	o := find(newTestDetector(fakeFS{}).Detect(snap), "ollama")
	if o == nil || !o.Running || len(o.ListeningPorts) != 1 {
		t.Fatalf("ollama: %+v", o)
	}
}

func TestClaudeCodeProjectsAndCodexTOML(t *testing.T) {
	fs := fakeFS{
		"/home/bob/.claude.json": `{"mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}},
		  "projects": {"/home/bob/src/api": {"mcpServers": {"pg": {"command": "pg-mcp", "args": []}}}}}`,
		"/home/bob/.codex/config.toml": `
model = "o4"
[mcp_servers.linear]
command = "npx"
args = ["-y", "mcp-remote", "https://mcp.linear.app/sse"]
env = { LINEAR_API_KEY = "lin_secret" }

[mcp_servers."k8s"]
command = "kubectl-mcp"
[mcp_servers."k8s".env]
KUBECONFIG = "/home/bob/.kube/config"
`,
	}
	got := newTestDetector(fs).Detect(Snapshot{OS: "linux", HomeDirs: []string{"/home/bob"}})
	cc := find(got, "claude_code")
	if cc == nil || len(cc.MCPServers) != 2 {
		t.Fatalf("claude_code: %+v", cc)
	}
	if cc.MCPServers[0].Transport != "http" || cc.MCPServers[1].Scope != "/home/bob/src/api" {
		t.Errorf("claude_code servers: %+v", cc.MCPServers)
	}
	cx := find(got, "codex_cli")
	if cx == nil || len(cx.MCPServers) != 2 {
		t.Fatalf("codex: %+v", cx)
	}
	if cx.MCPServers[0].Name != "linear" || strings.Join(cx.MCPServers[0].EnvKeys, ",") != "LINEAR_API_KEY" {
		t.Errorf("linear: %+v", cx.MCPServers[0])
	}
	if cx.MCPServers[1].Name != "k8s" || strings.Join(cx.MCPServers[1].ResourceHints, ",") != "kubernetes" ||
		strings.Join(cx.MCPServers[1].EnvKeys, ",") != "KUBECONFIG" {
		t.Errorf("k8s: %+v", cx.MCPServers[1])
	}
}

func TestExpandPath(t *testing.T) {
	cases := map[string]string{
		"macos":   "/Users/a/Library/Application Support/Claude/x.json",
		"linux":   "/Users/a/.config/Claude/x.json",
		"windows": "/Users/a/AppData/Roaming/Claude/x.json",
	}
	for goos, want := range cases {
		if got := filepath.ToSlash(expandPath("{config}/Claude/x.json", "/Users/a", goos)); got != want {
			t.Errorf("%s: got %s want %s", goos, got, want)
		}
	}
	if got := filepath.ToSlash(expandPath("~/.cursor/mcp.json", "/home/z", "linux")); got != "/home/z/.cursor/mcp.json" {
		t.Errorf("tilde: %s", got)
	}
}

func TestBuildGraph(t *testing.T) {
	agents := []DetectedAgent{{
		ID: "cursor", Running: true,
		MCPServers: []MCPServer{
			{Name: "github", User: "alice", ResourceHints: []string{"github"}},
			{Name: "db", User: "alice", ResourceHints: []string{"database:postgres"}},
		},
	}}
	g := BuildGraph("dev_1", agents)
	want := []Edge{
		{From: "device:dev_1", To: "agent:cursor", Relation: "runs"},
		{From: "agent:cursor", To: "mcp:github", Relation: "uses_mcp", User: "alice"},
		{From: "mcp:github", To: "resource:github", Relation: "accesses"},
		{From: "agent:cursor", To: "mcp:db", Relation: "uses_mcp", User: "alice"},
		{From: "mcp:db", To: "resource:database:postgres", Relation: "accesses"},
	}
	if len(g.Edges) != len(want) {
		t.Fatalf("edges: %+v", g.Edges)
	}
	for i := range want {
		if g.Edges[i] != want[i] {
			t.Errorf("edge %d: got %+v want %+v", i, g.Edges[i], want[i])
		}
	}
}

func TestMalformedConfigIgnored(t *testing.T) {
	fs := fakeFS{"/home/c/.cursor/mcp.json": `{not json`}
	if got := newTestDetector(fs).Detect(Snapshot{OS: "linux", HomeDirs: []string{"/home/c"}}); len(got) != 0 {
		t.Fatalf("malformed config should be ignored: %+v", got)
	}
	if _, err := LoadRegistry([]byte(`{"agents":[{"id":"x"}]}`)); err == nil {
		t.Fatal("registry without category must fail")
	}
}
