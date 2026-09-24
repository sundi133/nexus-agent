// Package detector identifies AI agents, AI assistants, MCP clients and local
// LLM runtimes on a device, and maps which MCP servers (tools) each one is
// wired to. The result is the agent → MCP server → resource graph the Votal
// cloud uses for policy and risk scoring.
package detector

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sundi133/nexus-agent/internal/platform"
)

//go:embed registry.json
var builtinRegistry []byte

// Categories of AI software.
const (
	CategoryCodingAgent = "ai_coding_agent"
	CategoryAssistant   = "ai_assistant"
	CategoryMCPClient   = "mcp_client"
	CategoryLocalLLM    = "local_llm"
)

// MCPConfigSpec points at a file declaring MCP servers.
type MCPConfigSpec struct {
	// Path supports "~" (user home) and "{config}" (per-OS user config dir).
	Path   string   `json:"path"`
	Format string   `json:"format"` // "json" | "toml"
	OS     []string `json:"os,omitempty"`
}

// Definition describes how to recognise one AI product.
type Definition struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Vendor        string          `json:"vendor"`
	Category      string          `json:"category"`
	Processes     []string        `json:"processes"`
	Apps          []string        `json:"apps"`
	BundleIDs     []string        `json:"bundle_ids"`
	Ports         []int           `json:"ports"`
	MCPConfigs    []MCPConfigSpec `json:"mcp_configs"`
	ExtensionDirs []string        `json:"extension_dirs"`
}

// Registry is the list of known AI products.
type Registry struct {
	Version int          `json:"version"`
	Agents  []Definition `json:"agents"`
}

// LoadRegistry parses a registry document.
func LoadRegistry(b []byte) (*Registry, error) {
	var r Registry
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	for i, d := range r.Agents {
		if d.ID == "" || d.Category == "" {
			return nil, fmt.Errorf("registry entry %d: id and category are required", i)
		}
	}
	return &r, nil
}

// BuiltinRegistry returns the registry compiled into the binary.
func BuiltinRegistry() *Registry {
	r, err := LoadRegistry(builtinRegistry)
	if err != nil {
		panic(err) // covered by tests; a broken embed is a build bug
	}
	return r
}

// Snapshot is the device state the detector evaluates.
type Snapshot struct {
	OS          string
	Processes   []platform.Process
	Apps        []platform.Application
	Connections []platform.Connection
	HomeDirs    []string
}

// DetectedAgent is one AI product found on the device.
type DetectedAgent struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Vendor         string      `json:"vendor,omitempty"`
	Category       string      `json:"category"`
	Installed      bool        `json:"installed"`
	Running        bool        `json:"running"`
	Version        string      `json:"version,omitempty"`
	AppPath        string      `json:"app_path,omitempty"`
	PIDs           []int       `json:"pids,omitempty"`
	Users          []string    `json:"users,omitempty"`
	ListeningPorts []int       `json:"listening_ports,omitempty"`
	Extensions     []string    `json:"extensions,omitempty"`
	MCPServers     []MCPServer `json:"mcp_servers,omitempty"`
}

// Edge is one relationship in the AI agent graph.
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	User     string `json:"user,omitempty"`
}

// Graph is the agent → MCP server → resource relationship graph.
type Graph struct {
	Edges []Edge `json:"edges"`
}

// Detector matches a Snapshot against a Registry.
type Detector struct {
	reg *Registry
	fs  fileSystem
}

// New creates a detector for the given registry.
func New(reg *Registry) *Detector { return &Detector{reg: reg, fs: osFS{}} }

// Detect returns every registry product with any evidence on the device.
func (d *Detector) Detect(s Snapshot) []DetectedAgent {
	var found []DetectedAgent
	for _, def := range d.reg.Agents {
		a := DetectedAgent{ID: def.ID, Name: def.Name, Vendor: def.Vendor, Category: def.Category}
		d.matchProcesses(&a, def, s)
		d.matchApps(&a, def, s)
		d.matchPorts(&a, def, s)
		d.matchExtensions(&a, def, s)
		for _, spec := range def.MCPConfigs {
			if len(spec.OS) > 0 && !contains(spec.OS, s.OS) {
				continue
			}
			for _, home := range s.HomeDirs {
				path := expandPath(spec.Path, home, s.OS)
				servers, err := d.readMCPConfig(path, spec.Format)
				if err != nil || len(servers) == 0 {
					continue
				}
				user := filepath.Base(home)
				for i := range servers {
					servers[i].User = user
				}
				a.MCPServers = append(a.MCPServers, servers...)
				a.Users = appendUnique(a.Users, user)
			}
		}
		if a.Running || a.Installed || len(a.MCPServers) > 0 || len(a.Extensions) > 0 {
			sort.Ints(a.PIDs)
			sort.Strings(a.Users)
			found = append(found, a)
		}
	}
	return found
}

// normalizeProcName strips a Windows ".exe" suffix. Matching is otherwise
// case-sensitive on purpose: "Claude" (Claude Desktop) and "claude"
// (Claude Code CLI) are different products.
func normalizeProcName(n string) string {
	if len(n) > 4 && strings.EqualFold(n[len(n)-4:], ".exe") {
		return n[:len(n)-4]
	}
	return n
}

func (d *Detector) matchProcesses(a *DetectedAgent, def Definition, s Snapshot) {
	names := map[string]bool{}
	for _, p := range def.Processes {
		names[normalizeProcName(p)] = true
	}
	for _, p := range s.Processes {
		if names[normalizeProcName(p.Name)] {
			a.Running = true
			a.PIDs = append(a.PIDs, p.PID)
			if p.User != "" {
				a.Users = appendUnique(a.Users, p.User)
			}
		}
	}
}

func (d *Detector) matchApps(a *DetectedAgent, def Definition, s Snapshot) {
	for _, app := range s.Apps {
		match := app.BundleID != "" && containsFold(def.BundleIDs, app.BundleID)
		if !match {
			match = containsFold(def.Apps, app.Name)
		}
		if match {
			a.Installed = true
			if a.Version == "" {
				a.Version = app.Version
			}
			if a.AppPath == "" {
				a.AppPath = app.Path
			}
		}
	}
}

func (d *Detector) matchPorts(a *DetectedAgent, def Definition, s Snapshot) {
	if len(def.Ports) == 0 {
		return
	}
	for _, c := range s.Connections {
		if c.State != "LISTEN" || !containsInt(def.Ports, c.LocalPort) {
			continue
		}
		// A listener on a well-known port only counts when owned by one of
		// the product's processes (port 8080 is shared by many servers), so
		// sockets with an unknown owner are ignored.
		if len(def.Processes) > 0 && !containsProcName(def.Processes, c.Process) {
			continue
		}
		a.ListeningPorts = appendUniqueInt(a.ListeningPorts, c.LocalPort)
		a.Running = true
	}
}

func (d *Detector) matchExtensions(a *DetectedAgent, def Definition, s Snapshot) {
	for _, pattern := range def.ExtensionDirs {
		for _, home := range s.HomeDirs {
			matches, _ := d.fs.Glob(expandPath(pattern, home, s.OS))
			for _, m := range matches {
				a.Extensions = appendUnique(a.Extensions, filepath.Base(m))
				a.Users = appendUnique(a.Users, filepath.Base(home))
			}
		}
	}
}

// BuildGraph flattens detections into relationship edges:
//
//	device ──runs──▶ agent ──uses_mcp──▶ mcp server ──accesses──▶ resource
func BuildGraph(deviceID string, agents []DetectedAgent) Graph {
	var g Graph
	seen := map[Edge]bool{}
	add := func(e Edge) {
		if !seen[e] {
			seen[e] = true
			g.Edges = append(g.Edges, e)
		}
	}
	dev := "device:" + deviceID
	for _, a := range agents {
		an := "agent:" + a.ID
		rel := "has_installed"
		if a.Running {
			rel = "runs"
		}
		add(Edge{From: dev, To: an, Relation: rel})
		for _, s := range a.MCPServers {
			sn := "mcp:" + s.Name
			add(Edge{From: an, To: sn, Relation: "uses_mcp", User: s.User})
			for _, r := range s.ResourceHints {
				add(Edge{From: sn, To: "resource:" + r, Relation: "accesses"})
			}
		}
	}
	return g
}

// expandPath resolves "~" and "{config}" for a given home directory.
func expandPath(p, home, goos string) string {
	var cfg string
	switch goos {
	case "macos", "darwin":
		cfg = filepath.Join(home, "Library", "Application Support")
	case "windows":
		cfg = filepath.Join(home, "AppData", "Roaming")
	default:
		cfg = filepath.Join(home, ".config")
	}
	p = strings.ReplaceAll(p, "{config}", cfg)
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return filepath.FromSlash(p)
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func containsProcName(xs []string, v string) bool {
	v = normalizeProcName(v)
	for _, x := range xs {
		if normalizeProcName(x) == v {
			return true
		}
	}
	return false
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func appendUnique(xs []string, v string) []string {
	if contains(xs, v) {
		return xs
	}
	return append(xs, v)
}

func appendUniqueInt(xs []int, v int) []int {
	if containsInt(xs, v) {
		return xs
	}
	return append(xs, v)
}
