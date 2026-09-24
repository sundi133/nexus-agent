package detector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MCPServer is one MCP server an AI client is configured to launch or call.
// Secrets are never reported: env and header *values* are dropped and
// credential-looking arguments are redacted on-device.
type MCPServer struct {
	Name          string   `json:"name"`
	Transport     string   `json:"transport"` // stdio | http | sse
	Command       string   `json:"command,omitempty"`
	Args          []string `json:"args,omitempty"`
	URL           string   `json:"url,omitempty"`
	EnvKeys       []string `json:"env_keys,omitempty"`
	HeaderKeys    []string `json:"header_keys,omitempty"`
	ConfigPath    string   `json:"config_path"`
	Scope         string   `json:"scope,omitempty"` // "user" or a project path
	User          string   `json:"user,omitempty"`
	ResourceHints []string `json:"resource_hints,omitempty"`
}

// maxConfigBytes caps config reads (~/.claude.json can grow large).
const maxConfigBytes = 16 << 20

type fileSystem interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

type osFS struct{}

func (osFS) ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigBytes {
		return nil, errors.New("config file too large")
	}
	return b, nil
}

func (osFS) Glob(p string) ([]string, error) { return filepath.Glob(p) }

func (d *Detector) readMCPConfig(path, format string) ([]MCPServer, error) {
	b, err := d.fs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch format {
	case "toml":
		return parseTOMLMCP(string(b), path), nil
	default:
		return parseJSONMCP(b, path)
	}
}

// rawServer covers the union of field names used by MCP clients.
type rawServer struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]any    `json:"env"`
	URL       string            `json:"url"`
	ServerURL string            `json:"serverUrl"` // Windsurf
	HTTPURL   string            `json:"httpUrl"`   // Gemini CLI
	Type      string            `json:"type"`
	Transport string            `json:"transport"`
	Headers   map[string]string `json:"headers"`
}

// parseJSONMCP understands:
//
//	{"mcpServers": {...}}                        Claude Desktop, Cursor, Windsurf, Gemini, Claude Code
//	{"servers": {...}}                           VS Code mcp.json
//	{"projects": {"/path": {"mcpServers": {...}}}}  Claude Code per-project servers
func parseJSONMCP(b []byte, path string) ([]MCPServer, error) {
	var doc struct {
		MCPServers map[string]rawServer `json:"mcpServers"`
		Servers    map[string]rawServer `json:"servers"`
		Projects   map[string]struct {
			MCPServers map[string]rawServer `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []MCPServer
	out = append(out, convertServers(doc.MCPServers, path, "user")...)
	out = append(out, convertServers(doc.Servers, path, "user")...)
	projects := make([]string, 0, len(doc.Projects))
	for p := range doc.Projects {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for _, p := range projects {
		out = append(out, convertServers(doc.Projects[p].MCPServers, path, p)...)
	}
	return out, nil
}

func convertServers(m map[string]rawServer, path, scope string) []MCPServer {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []MCPServer
	for _, name := range names {
		r := m[name]
		s := MCPServer{Name: name, ConfigPath: path, Scope: scope, Command: r.Command}
		s.URL = firstNonEmpty(r.URL, r.ServerURL, r.HTTPURL)
		s.Transport = transportOf(firstNonEmpty(r.Type, r.Transport), s.Command, s.URL)
		s.Args = RedactArgs(r.Args)
		s.URL = RedactURL(s.URL)
		s.EnvKeys = sortedKeys(r.Env)
		s.HeaderKeys = sortedKeys(r.Headers)
		s.ResourceHints = ResourceHints(s)
		out = append(out, s)
	}
	return out
}

func transportOf(declared, command, u string) string {
	switch strings.ToLower(declared) {
	case "stdio":
		return "stdio"
	case "sse":
		return "sse"
	case "http", "streamable-http", "streamablehttp":
		return "http"
	}
	if command != "" {
		return "stdio"
	}
	if strings.Contains(u, "/sse") {
		return "sse"
	}
	if u != "" {
		return "http"
	}
	return "unknown"
}

var tomlSection = regexp.MustCompile(`^\[\s*mcp_servers\.("?)([^\]"]+)("?)(\.env)?\s*\]$`)

// parseTOMLMCP extracts [mcp_servers.<name>] tables (Codex CLI) without a
// full TOML parser: string, string-array, and env sub-table keys only.
func parseTOMLMCP(content, path string) []MCPServer {
	servers := map[string]*MCPServer{}
	var order []string
	var cur *MCPServer
	inEnv := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			m := tomlSection.FindStringSubmatch(line)
			if m == nil {
				cur = nil
				continue
			}
			name := m[2]
			if servers[name] == nil {
				servers[name] = &MCPServer{Name: name, ConfigPath: path, Scope: "user"}
				order = append(order, name)
			}
			cur, inEnv = servers[name], m[4] != ""
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if inEnv {
			cur.EnvKeys = append(cur.EnvKeys, strings.Trim(k, `"`))
			continue
		}
		switch k {
		case "command":
			cur.Command = tomlString(v)
		case "url":
			cur.URL = tomlString(v)
		case "args":
			var arr []string
			if json.Unmarshal([]byte(v), &arr) == nil {
				cur.Args = arr
			}
		case "env":
			// inline table: env = { KEY = "v", ... }
			inner := strings.Trim(v, "{} ")
			for _, kv := range strings.Split(inner, ",") {
				if key, _, ok := strings.Cut(kv, "="); ok {
					cur.EnvKeys = append(cur.EnvKeys, strings.Trim(strings.TrimSpace(key), `"`))
				}
			}
		}
	}
	var out []MCPServer
	for _, n := range order {
		s := *servers[n]
		s.Transport = transportOf("", s.Command, s.URL)
		s.Args = RedactArgs(s.Args)
		s.URL = RedactURL(s.URL)
		sort.Strings(s.EnvKeys)
		s.ResourceHints = ResourceHints(s)
		out = append(out, s)
	}
	return out
}

func tomlString(v string) string {
	if strings.HasPrefix(v, `"`) {
		var s string
		if json.Unmarshal([]byte(v), &s) == nil {
			return s
		}
	}
	return strings.Trim(v, `'"`)
}

// ---- redaction -------------------------------------------------------------

const redacted = "[REDACTED]"

var (
	secretName   = regexp.MustCompile(`(?i)(token|secret|password|passwd|pwd|api[-_]?key|apikey|auth|credential|private[-_]?key|access[-_]?key)`)
	secretValues = regexp.MustCompile(`^(sk-[A-Za-z0-9_-]{8,}|sk_(live|test)_[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})$`)
)

// RedactArgs removes credentials from a command's argument list.
func RedactArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	prevSecretFlag := false
	for i, a := range args {
		switch {
		case prevSecretFlag && !strings.HasPrefix(a, "-"):
			out[i] = redacted
		case strings.Contains(a, "=") && strings.HasPrefix(a, "-"):
			k, _, _ := strings.Cut(a, "=")
			if secretName.MatchString(k) {
				out[i] = k + "=" + redacted
			} else {
				out[i] = a
			}
		case secretValues.MatchString(a):
			out[i] = redacted
		case strings.Contains(a, "://"):
			out[i] = RedactURL(a)
		default:
			out[i] = a
		}
		prevSecretFlag = strings.HasPrefix(a, "-") && !strings.Contains(a, "=") && secretName.MatchString(a)
	}
	return out
}

// RedactURL strips passwords and secret-looking query values from a URL
// (e.g. postgres://user:pass@db/x or https://h/mcp?api_key=...).
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	if u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), "REDACTED")
		}
	}
	q := u.Query()
	changed := false
	for k := range q {
		if secretName.MatchString(k) || k == "key" || k == "sig" {
			q.Set(k, "REDACTED")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// ---- resource classification -------------------------------------------------

// resourceKeywords maps substrings found in an MCP server's name, command,
// args or URL to the resource class it most likely grants access to.
var resourceKeywords = []struct{ kw, resource string }{
	{"github", "github"}, {"gitlab", "gitlab"}, {"bitbucket", "bitbucket"},
	{"postgres", "database:postgres"}, {"supabase", "database:postgres"}, {"neon", "database:postgres"},
	{"mysql", "database:mysql"}, {"mariadb", "database:mysql"},
	{"sqlite", "database:sqlite"}, {"mongo", "database:mongodb"}, {"redis", "database:redis"},
	{"snowflake", "database:snowflake"}, {"bigquery", "database:bigquery"}, {"clickhouse", "database:clickhouse"},
	{"filesystem", "filesystem"}, {"slack", "slack"}, {"jira", "jira"}, {"atlassian", "atlassian"},
	{"confluence", "atlassian"}, {"linear", "linear"}, {"notion", "notion"},
	{"gdrive", "google_drive"}, {"google-drive", "google_drive"}, {"gmail", "gmail"},
	{"aws", "cloud:aws"}, {"gcp", "cloud:gcp"}, {"azure", "cloud:azure"},
	{"kubernetes", "kubernetes"}, {"k8s", "kubernetes"}, {"docker", "docker"},
	{"stripe", "stripe"}, {"sentry", "sentry"}, {"salesforce", "salesforce"},
	{"puppeteer", "browser"}, {"playwright", "browser"}, {"browser", "browser"},
	{"shell", "shell"}, {"terminal", "shell"},
}

// ResourceHints guesses which resource classes an MCP server touches.
func ResourceHints(s MCPServer) []string {
	hay := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " ") + " " + s.URL)
	var hints []string
	for _, rk := range resourceKeywords {
		if strings.Contains(hay, rk.kw) {
			hints = appendUnique(hints, rk.resource)
		}
	}
	sort.Strings(hints)
	return hints
}

func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
