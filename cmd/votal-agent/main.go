// Command votal-agent is the Votal endpoint agent.
//
//	votal-agent run      [-config PATH]   run the agent (foreground or as a service)
//	votal-agent enroll   [-config PATH]   enroll this device and exit
//	votal-agent configure -server-url URL -enrollment-token TOKEN   write config (installers/MDM)
//	votal-agent collect  [-pretty]        print a local telemetry snapshot (no cloud)
//	votal-agent detect   [-pretty]        print detected AI agents and MCP graph (no cloud)
//	votal-agent decide   -resource R -action A [-user U] [-agent ID] [-tool T] [-policy FILE]
//	votal-agent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sundi133/nexus-agent/internal/agent"
	"github.com/sundi133/nexus-agent/internal/config"
	"github.com/sundi133/nexus-agent/internal/detector"
	"github.com/sundi133/nexus-agent/internal/osquery"
	"github.com/sundi133/nexus-agent/internal/platform"
	"github.com/sundi133/nexus-agent/internal/policy"
	"github.com/sundi133/nexus-agent/internal/secure"
	"github.com/sundi133/nexus-agent/internal/service"
	"github.com/sundi133/nexus-agent/internal/telemetry"
	"github.com/sundi133/nexus-agent/internal/version"
)

// Exit codes. 3 tells the service manager a restart is wanted (self-update).
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitRestart = 3
	exitDenied  = 4 // `decide` returned deny
)

func main() { os.Exit(realMain(os.Args[1:])) }

func realMain(args []string) int {
	if len(args) == 0 {
		// Service managers invoke the binary with "run"; bare invocation
		// under the Windows SCM also means run.
		if service.IsService() {
			args = []string{"run"}
		} else {
			usage()
			return exitUsage
		}
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(rest)
	case "enroll":
		return cmdEnroll(rest)
	case "configure":
		return cmdConfigure(rest)
	case "collect":
		return cmdCollect(rest)
	case "detect":
		return cmdDetect(rest)
	case "decide":
		return cmdDecide(rest)
	case "version", "-v", "--version":
		fmt.Println(version.String())
		return exitOK
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Votal endpoint agent

Usage:
  votal-agent run      [-config PATH] [-log-file PATH]
  votal-agent enroll   [-config PATH]
  votal-agent configure -server-url URL [-enrollment-token TOKEN] [-config PATH]
  votal-agent collect  [-pretty]
  votal-agent detect   [-pretty]
  votal-agent decide   -resource R -action A [-user U] [-agent ID] [-tool T] [-policy FILE] [-config PATH]
  votal-agent version
`)
}

// ---- run / enroll ---------------------------------------------------------

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file")
	logFile := fs.String("log-file", defaultLogFile(), "log file (empty = stderr)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return exitError
	}
	log, closeLog, err := newLogger(cfg.LogLevel, *logFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "log:", err)
		return exitError
	}
	defer closeLog()

	a, err := agent.New(cfg, log)
	if err != nil {
		log.Error("init failed", "err", err)
		return exitError
	}
	err = service.Run(a.Run)
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		return exitOK
	case errors.Is(err, agent.ErrRestartRequired):
		return exitRestart
	default:
		log.Error("agent exited", "err", err)
		return exitError
	}
}

func cmdEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file")
	timeout := fs.Duration("timeout", 2*time.Minute, "give up after")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return exitError
	}
	log, closeLog, _ := newLogger(cfg.LogLevel, "")
	defer closeLog()
	a, err := agent.New(cfg, log)
	if err != nil {
		log.Error("init failed", "err", err)
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := a.Enroll(ctx); err != nil {
		log.Error("enrollment failed", "err", err)
		return exitError
	}
	fmt.Println(a.DeviceID())
	return exitOK
}

// cmdConfigure writes/merges the config file. Installers (MSI custom action,
// pkg postinstall, deb/rpm postinst) and MDM scripts call this so the
// enrollment token never has to be templated into a world-readable file.
func cmdConfigure(args []string) int {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file to write")
	serverURL := fs.String("server-url", "", "Votal cloud URL")
	token := fs.String("enrollment-token", "", "enrollment token")
	_ = fs.Parse(args)

	cfg := config.Default()
	if b, err := os.ReadFile(*cfgPath); err == nil {
		if err := json.Unmarshal(b, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "existing config is invalid:", err)
			return exitError
		}
	}
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *token != "" {
		cfg.EnrollmentToken = *token
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return exitError
	}
	if err := secure.RestrictDir(filepath.Dir(*cfgPath)); err != nil {
		fmt.Fprintln(os.Stderr, "secure config dir:", err)
		return exitError
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(*cfgPath, append(b, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	fmt.Println("wrote", *cfgPath)
	return exitOK
}

// ---- offline diagnostics ----------------------------------------------------

func cmdCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	pretty := fs.Bool("pretty", true, "indent output")
	osq := fs.String("osquery", "", `osqueryi path, or "disabled"`)
	_ = fs.Parse(args)

	log, closeLog, _ := newLogger("warn", "")
	defer closeLog()
	c := telemetry.NewCollector(platform.New(), osquery.New(*osq), detector.New(detector.BuiltinRegistry()), log)
	res := c.Collect(context.Background(), "local")

	out := map[string]json.RawMessage{}
	for _, e := range res.Events {
		out[e.Type] = e.Data
	}
	return printJSON(out, *pretty)
}

func cmdDetect(args []string) int {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	pretty := fs.Bool("pretty", true, "indent output")
	_ = fs.Parse(args)

	ctx := context.Background()
	p := platform.New()
	procs, _ := p.Processes(ctx)
	conns, _ := p.NetworkConnections(ctx)
	apps, _ := p.InstalledApps(ctx)
	found := detector.New(detector.BuiltinRegistry()).Detect(detector.Snapshot{
		OS: p.OS(), Processes: procs, Apps: apps, Connections: conns, HomeDirs: p.UserHomeDirs(),
	})
	return printJSON(map[string]any{
		"agents": found,
		"graph":  detector.BuildGraph("local", found),
	}, *pretty)
}

func cmdDecide(args []string) int {
	fs := flag.NewFlagSet("decide", flag.ExitOnError)
	policyFile := fs.String("policy", "", "policy bundle JSON (default: cached bundle from state dir)")
	cfgPath := fs.String("config", config.DefaultPath(), "config file (for state_dir)")
	var req policy.Request
	fs.StringVar(&req.User, "user", "", "user")
	fs.StringVar(&req.AgentID, "agent", "", "AI agent id (e.g. cursor)")
	fs.StringVar(&req.AgentType, "agent-type", "", "AI agent category (derived from -agent if empty)")
	fs.StringVar(&req.Tool, "tool", "", "tool name")
	fs.StringVar(&req.Resource, "resource", "", "resource")
	fs.StringVar(&req.Action, "action", "", "action")
	_ = fs.Parse(args)

	var bundle *policy.Bundle
	if *policyFile != "" {
		b, err := os.ReadFile(*policyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		bundle = &policy.Bundle{}
		if err := json.Unmarshal(b, bundle); err != nil {
			fmt.Fprintln(os.Stderr, "parse policy:", err)
			return exitError
		}
		if err := bundle.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "invalid policy:", err)
			return exitError
		}
	} else {
		stateDir := config.DefaultStateDir()
		if cfg, err := config.Load(*cfgPath); err == nil {
			stateDir = cfg.StateDir
		}
		store, err := policy.NewStore(filepath.Join(stateDir, "policy.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		bundle, _ = store.Get()
	}
	if req.AgentType == "" && req.AgentID != "" {
		for _, d := range detector.BuiltinRegistry().Agents {
			if strings.EqualFold(d.ID, req.AgentID) {
				req.AgentType = d.Category
			}
		}
	}
	res := policy.Evaluate(bundle, policy.Environment{OS: platform.New().OS()}, req)
	printJSON(res, true)
	if res.Decision == policy.Deny {
		return exitDenied
	}
	return exitOK
}

func printJSON(v any, pretty bool) int {
	enc := json.NewEncoder(os.Stdout)
	if pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	return exitOK
}

// ---- logging --------------------------------------------------------------------

func defaultLogFile() string {
	// launchd and systemd capture stderr; the Windows SCM does not.
	if runtime.GOOS == "windows" && service.IsService() {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "Votal", "logs", "agent.log")
	}
	return ""
}

func newLogger(level, file string) (*slog.Logger, func(), error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	var w io.Writer = os.Stderr
	closeFn := func() {}
	if file != "" {
		rw, err := newRotatingWriter(file, 10<<20)
		if err != nil {
			return nil, nil, err
		}
		w, closeFn = rw, func() { rw.Close() }
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})), closeFn, nil
}
