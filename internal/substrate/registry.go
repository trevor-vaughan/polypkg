package substrate

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// config holds construction-time settings shared by every substrate. It is
// populated by Option values and consumed by the concrete constructor.
type config struct {
	dirMode os.FileMode
}

// Option configures a substrate at construction. Options are collected by New /
// the registry Factory and applied by the concrete constructor.
type Option func(*config)

// WithDirMode sets the directory-creation mode for the substrate's write-path
// MkdirAlls. The zero value (the default when no option is passed) means 0o700
// — user-private. System scope passes 0o755 so a multi-user install's
// generation and active-tree directories are traversable by other users.
func WithDirMode(mode os.FileMode) Option {
	return func(c *config) { c.dirMode = mode }
}

// Factory constructs a substrate rooted at the given scope data directory,
// applying any construction options (e.g. the directory mode).
type Factory func(root string, opts ...Option) (Substrate, error)

// registry maps a substrate name (as written in scopes.<name>.substrate) to its
// factory. Only the own-store exists; another substrate (e.g. sysext) adds one
// entry here.
var registry = map[string]Factory{
	"store": func(root string, opts ...Option) (Substrate, error) { return NewOwnStore(root, opts...) },
}

// New constructs the named substrate rooted at root, or fails closed when the
// name is unknown or unimplemented (an empty name is always unavailable).
func New(name, root string, opts ...Option) (Substrate, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unsupported substrate %q (available: %s)", name, available())
	}
	return f(root, opts...)
}

// Validate reports whether name is an available substrate without constructing
// it, for plan-time checks. It returns the same error as New.
func Validate(name string) error {
	if _, ok := registry[name]; !ok {
		return fmt.Errorf("unsupported substrate %q (available: %s)", name, available())
	}
	return nil
}

func available() string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
