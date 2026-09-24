package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"server_url":"https://api.votal.ai/","intervals":{"heartbeat":"15s","telemetry":300}}`), 0o600)
	t.Setenv("VOTAL_ENROLLMENT_TOKEN", "from-env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "https://api.votal.ai" {
		t.Errorf("trailing slash not trimmed: %q", cfg.ServerURL)
	}
	if cfg.EnrollmentToken != "from-env" {
		t.Errorf("env override: %q", cfg.EnrollmentToken)
	}
	if cfg.Intervals.Heartbeat.Duration != 15*time.Second || cfg.Intervals.Telemetry.Duration != 5*time.Minute {
		t.Errorf("intervals: %+v", cfg.Intervals)
	}
	if cfg.Intervals.Policy.Duration != 5*time.Minute {
		t.Errorf("default policy interval lost: %v", cfg.Intervals.Policy)
	}
}

func TestValidateRequiresHTTPS(t *testing.T) {
	c := Default()
	c.ServerURL = "http://api.votal.ai"
	if err := c.Validate(); err == nil {
		t.Fatal("http accepted without allow_insecure_http")
	}
	c.AllowInsecureHTTP = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.ServerURL = ""
	if err := c.Validate(); err == nil {
		t.Fatal("empty server_url accepted")
	}
	c = Default()
	c.ServerURL = "https://x"
	c.Intervals.Heartbeat.Duration = 0
	if err := c.Validate(); err == nil {
		t.Fatal("zero interval accepted")
	}
}

func TestMissingFileUsesEnv(t *testing.T) {
	t.Setenv("VOTAL_SERVER_URL", "https://env.votal.ai")
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "https://env.votal.ai" {
		t.Fatal(cfg.ServerURL)
	}
}
