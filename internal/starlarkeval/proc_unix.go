//go:build unix

package starlarkeval

import (
	"os/exec"
	"syscall"
)

// setProcAttr puts the child in its own process group so the parent can kill the
// whole group on timeout/limit breach.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killChild kills the child's process group.
func killChild(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
