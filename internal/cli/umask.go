package cli

import "syscall"

// setUmask sets the process umask to mask and returns a function that restores
// the previous umask. A system-scope apply pins a 0o022 umask so the declared
// directory modes (0o755 traversable trees, 0o700 private subtrees) and file
// modes (0o600/0o644) are produced exactly, independent of the operator's
// inherited umask. Without this, a restrictive root umask (e.g. 0o027 or 0o077,
// common on hardened hosts) would silently strip the group/other traversal bits
// that a multi-user system install needs — defeating the whole point of the
// 0o755 modes with no error. umask 0o022 only clears group/other *write* bits,
// so it never widens the explicit 0o600/0o644 file modes or the 0o700 private
// dirs; it only guarantees the 0o755 dirs keep their traversal bits.
//
// polypkg is *NIX-only (e.g. internal/lock and internal/schema already use
// untagged unix syscalls like syscall.Flock/syscall.Stat_t and never build for
// Windows), so syscall.Umask introduces no new portability surface.
func setUmask(mask int) (restore func()) {
	old := syscall.Umask(mask)
	return func() { _ = syscall.Umask(old) }
}
