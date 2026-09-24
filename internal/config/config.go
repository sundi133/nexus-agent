// Package config loads the agent configuration from disk and environment.
//
// The config file is JSON so the agent has no third-party parser dependency.
// Default locations:
//
//	macOS:   /Library/Application Support/Votal/config.json
//	Windows: %ProgramData%\Votal\config.json
//	Linux:   /etc/votal/config.json
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Duration is a time.Duration that marshals to/from strings like "30s".
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Accept plain numbers as seconds.
		var n float64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"30s\": %w", err)
		}
		d.Duration = time.Duration(n * float64(time.Second))
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Intervals controls how often each agent loop runs.
type Intervals struct {
	Heartbeat Duration `json:"heartbeat"`
	Telemetry Duration `json:"telemetry"`
	Policy    Duration `json:"policy"`
	Commands  Duration `json:"commands"`
	Updates   Duration `json:"updates"`
}

// Config is the on-disk agent configuration.
type Config struct {
	// ServerURL is the Votal cloud base URL, e.g. https://api.votal.ai.
	ServerURL string `json:"server_url"`
	// EnrollmentToken is a one-time/org token used for first registration.
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	// StateDir stores the device identity and cached policy.
	StateDir string `json:"state_dir"`
	// CAFile optionally pins a custom CA bundle for the cloud API.
	CAFile string `json:"ca_file,omitempty"`
	// AllowInsecureHTTP permits http:// server URLs (development only).
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`

	Intervals Intervals `json:"intervals"`

	// LocalAPIAddr is where the local policy decision API listens.
	// Must be a loopback address. Empty disables it.
	LocalAPIAddr string `json:"local_api_addr"`

	// OsqueryPath overrides osqueryi discovery. "disabled" turns osquery off.
	OsqueryPath string `json:"osquery_path,omitempty"`

	// UpdatePublicKey is the base64 ed25519 key that must sign updates.
	// When empty, self-update is disabled.
	UpdatePublicKey string `json:"update_public_key,omitempty"`

	// LogLevel is one of debug, info, warn, error.
	LogLevel string `json:"log_level"`
}

// DefaultPath returns the platform config file location.
func DefaultPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Votal/config.json"
	case "windows":
		return filepath.Join(programData(), "Votal", "config.json")
	default:
		return "/etc/votal/config.json"
	}
}

// DefaultStateDir returns the platform state directory.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Votal/state"
	case "windows":
		return filepath.Join(programData(), "Votal", "state")
	default:
		return "/var/lib/votal"
	}
}

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// Default returns a config populated with defaults.
func Default() *Config {
	return &Config{
		StateDir: DefaultStateDir(),
		Intervals: Intervals{
			Heartbeat: Duration{60 * time.Second},
			Telemetry: Duration{15 * time.Minute},
			Policy:    Duration{5 * time.Minute},
			Commands:  Duration{30 * time.Second},
			Updates:   Duration{6 * time.Hour},
		},
		LocalAPIAddr: "127.0.0.1:7443",
		LogLevel:     "info",
	}
}

// Load reads the config file at path (if it exists), applies environment
// overrides, and validates the result. A missing file is not an error as long
// as the environment supplies the required values.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(b, cfg); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
			// fall through to env
		default:
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	cfg.applyEnv()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("VOTAL_SERVER_URL"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("VOTAL_ENROLLMENT_TOKEN"); v != "" {
		c.EnrollmentToken = v
	}
	if v := os.Getenv("VOTAL_STATE_DIR"); v != "" {
		c.StateDir = v
	}
	if v := os.Getenv("VOTAL_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("VOTAL_LOCAL_API_ADDR"); v != "" {
		c.LocalAPIAddr = v
	}
}

// Validate checks required fields and security constraints.
func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return errors.New("server_url is required (config file or VOTAL_SERVER_URL)")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server_url %q", c.ServerURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && c.AllowInsecureHTTP) {
		return fmt.Errorf("server_url must use https (set allow_insecure_http for development)")
	}
	c.ServerURL = strings.TrimRight(c.ServerURL, "/")
	if c.StateDir == "" {
		return errors.New("state_dir is required")
	}
	for name, d := range map[string]time.Duration{
		"heartbeat": c.Intervals.Heartbeat.Duration,
		"telemetry": c.Intervals.Telemetry.Duration,
		"policy":    c.Intervals.Policy.Duration,
		"commands":  c.Intervals.Commands.Duration,
		"updates":   c.Intervals.Updates.Duration,
	} {
		if d < time.Second {
			return fmt.Errorf("intervals.%s must be at least 1s", name)
		}
	}
	return nil
}
