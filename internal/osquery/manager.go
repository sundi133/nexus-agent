// Package osquery runs read-only queries through a locally installed
// osqueryi binary, so the agent does not have to reimplement the hundreds of
// inventory tables osquery already maintains.
package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ErrUnavailable is returned when osquery is not installed or disabled.
var ErrUnavailable = errors.New("osquery unavailable")

// Row is one result row; osquery returns every column as a string.
type Row map[string]string

// Manager executes osquery SQL.
type Manager struct {
	path    string
	timeout time.Duration
}

// candidatePaths lists default osqueryi install locations per OS.
func candidatePaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd",
			"/usr/local/bin/osqueryi",
			"/opt/homebrew/bin/osqueryi",
		}
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return []string{pf + `\osquery\osqueryi.exe`}
	default:
		return []string{"/usr/bin/osqueryi", "/opt/osquery/bin/osqueryi", "/usr/local/bin/osqueryi"}
	}
}

// New discovers osquery. override may be an explicit path, "disabled", or "".
func New(override string) *Manager {
	m := &Manager{timeout: 60 * time.Second}
	switch override {
	case "disabled":
		return m
	case "":
		for _, p := range candidatePaths() {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				m.path = p
				break
			}
		}
		if m.path == "" {
			if p, err := exec.LookPath("osqueryi"); err == nil {
				m.path = p
			}
		}
	default:
		m.path = override
	}
	return m
}

// Available reports whether an osquery binary was found.
func (m *Manager) Available() bool { return m != nil && m.path != "" }

// Path returns the resolved binary path.
func (m *Manager) Path() string { return m.path }

// ValidateQuery rejects anything that is not a single read-only SELECT.
// osqueryi is already read-only for most tables, but queries can arrive from
// the cloud, so we enforce this defensively on-device as well.
func ValidateQuery(sql string) error {
	q := strings.TrimSpace(sql)
	q = strings.TrimSuffix(q, ";")
	if q == "" {
		return errors.New("empty query")
	}
	if strings.Contains(q, ";") {
		return errors.New("multiple statements are not allowed")
	}
	lower := strings.ToLower(q)
	if !strings.HasPrefix(lower, "select") && !strings.HasPrefix(lower, "with") {
		return errors.New("only SELECT queries are allowed")
	}
	for _, kw := range []string{"attach", "insert", "update ", "delete", "drop", "create", "pragma", "alter"} {
		if containsWord(lower, kw) {
			return fmt.Errorf("keyword %q is not allowed", strings.TrimSpace(kw))
		}
	}
	return nil
}

func containsWord(s, word string) bool {
	word = strings.TrimSpace(word)
	for i := 0; ; {
		j := strings.Index(s[i:], word)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(word)
		before := start == 0 || !isIdent(s[start-1])
		after := end == len(s) || !isIdent(s[end])
		if before && after {
			return true
		}
		i = end
	}
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// Query runs sql and returns the rows.
func (m *Manager) Query(ctx context.Context, sql string) ([]Row, error) {
	if !m.Available() {
		return nil, ErrUnavailable
	}
	if err := ValidateQuery(sql); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	args := []string{"--json", "--disable_extensions", "--disable_events"}
	if strings.HasSuffix(m.path, "osqueryd") {
		// The macOS .app bundle ships osqueryd; it acts as osqueryi with -S.
		args = append([]string{"-S"}, args...)
	}
	args = append(args, sql)
	cmd := exec.CommandContext(ctx, m.path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("osquery: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var rows []Row
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		return nil, fmt.Errorf("osquery: decode: %w", err)
	}
	return rows, nil
}

// Standard inventory queries per OS. The telemetry collector prefers these
// over the native platform module when osquery is present.
func AppsQuery() string {
	switch runtime.GOOS {
	case "darwin":
		return "SELECT name, bundle_short_version AS version, path, bundle_identifier AS bundle_id FROM apps"
	case "windows":
		return "SELECT name, version, install_location AS path, publisher FROM programs"
	default:
		return "SELECT name, version, '' AS path, 'deb' AS source FROM deb_packages UNION ALL SELECT name, version, '' AS path, 'rpm' AS source FROM rpm_packages"
	}
}
