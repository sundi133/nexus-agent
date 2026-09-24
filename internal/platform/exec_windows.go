//go:build windows

package platform

import (
	"os/exec"
	"syscall"
)

// hideWindow prevents console windows flashing when the service shells out.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
