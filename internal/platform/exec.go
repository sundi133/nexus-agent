package platform

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// defaultCmdTimeout bounds every external tool invocation so a hung OS
// utility can never stall the agent.
const defaultCmdTimeout = 20 * time.Second

// run executes a program (never via a shell) and returns trimmed stdout.
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	hideWindow(cmd)
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return strings.TrimSpace(stdout.String()), fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// boolCheck converts a tri-state probe into a PostureCheck.
func boolCheck(id string, ok bool, err error, detail string) PostureCheck {
	if err != nil {
		return PostureCheck{ID: id, Status: StatusUnknown, Detail: err.Error()}
	}
	if ok {
		return PostureCheck{ID: id, Status: StatusPass, Detail: detail}
	}
	return PostureCheck{ID: id, Status: StatusFail, Detail: detail}
}
