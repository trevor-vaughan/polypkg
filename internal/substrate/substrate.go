// Package substrate defines polypkg's substrate-backend interface and
// ships the own-store substrate for M1.
package substrate

import (
	"errors"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// ErrNoCurrentGeneration is returned by CurrentOwnership when no generation has
// ever been committed (no active symlink). Callers detect first-apply with
// errors.Is.
var ErrNoCurrentGeneration = errors.New("no current generation")

// GenInfo summarises one retained generation for the GC algorithm and for
// any UX that wants to list generations (e.g., a future status display).
// BytesOnDisk is best-effort: a walk error during sizing degrades to 0
// rather than failing the enumeration.
type GenInfo struct {
	ID           int
	CommittedAt  time.Time
	Pinned       bool
	PinnedReason string
	IsCurrent    bool
	BytesOnDisk  int64
}

// Substrate is the interface that each substrate backend implements.
type Substrate interface {
	BeginTransaction(txID string) error
	CommitGeneration(txID string, m *schema.Manifest, own *schema.Ownership, configBases map[string][]byte) (int, error)
	Abort(txID string) error
	Rollback(genID int) error
	CurrentGeneration() (int, error)
	// StagingRoot returns the directory where actions should place files for the
	// given (begun, not-yet-committed) transaction. After commit, this directory
	// becomes the active generation.
	StagingRoot(txID string) (string, error)
	// CurrentOwnership returns the current generation's ownership index, its
	// generation ID, and the absolute path of its live active directory. It
	// returns ErrNoCurrentGeneration when no generation has ever been committed
	// (first apply). The generation ID is returned alongside the index so
	// callers can correlate accept-drift overrides without a second
	// CurrentGeneration call.
	CurrentOwnership() (*schema.Ownership, int, string, error)
	// ListGenerations enumerates every retained generation in the substrate,
	// including the currently active one. Order is unspecified; callers sort.
	ListGenerations() ([]GenInfo, error)
	// ReadManifest parses generations/<id>/manifest.json. Callers use it to
	// derive cross-generation reference sets (e.g. which extract-store dirs
	// retained generations still depend on).
	ReadManifest(id int) (*schema.Manifest, error)
	// PinGeneration writes pin.json next to manifest.json. Errors if the
	// generation does not exist or is already pinned. PinnedAt is set to
	// time.Now().UTC(); PinnedBy is taken from $USER or "unknown".
	PinGeneration(id int, reason string) error
	// UnpinGeneration removes the per-generation pin.json. Idempotent: a
	// no-op success when the generation is not currently pinned. Errors if
	// the generation does not exist.
	UnpinGeneration(id int) error
	// RemoveGeneration destroys the named generation's storage. Refuses if
	// the generation is currently active OR pinned; callers must Unpin first
	// to remove a pinned generation.
	RemoveGeneration(id int) error
	// StateRoot returns the absolute path of the stable state area (<root>/state),
	// a sibling of generations/ that is never touched by the swap, GC, or rollback.
	StateRoot() string
	// PurgeState removes the package's stable state directory recursively.
	// Idempotent: a nil return when the directory does not exist.
	PurgeState(pkg string) error
	// AltRoot returns the absolute path of the stable alternatives area
	// (<root>/alternatives), a sibling of generations/ and state/ that is never
	// touched by the swap, GC, or rollback. It holds the alternatives action's
	// mutable middle links.
	AltRoot() string
	// ActiveBinDir returns the absolute path of the active generation's shared
	// bin directory (<root>/active/bin), via the swap-stable "active" symlink.
	ActiveBinDir() string
	// ActiveCompletionsDir returns the absolute path of the active generation's
	// shared completions directory (<root>/active/completions), reached through
	// the active symlink. The completion installer links host shell dirs to
	// <ActiveCompletionsDir>/<shell>/<file>.
	ActiveCompletionsDir() string
	// ActiveDesktopDir returns the absolute path of the active generation's
	// shared applications directory (<root>/active/applications), reached through
	// the active symlink. The desktop installer links host applications dirs to
	// <ActiveDesktopDir>/<file>.
	ActiveDesktopDir() string
	// ActiveMimeDir returns the absolute path of the active generation's shared
	// mime directory (<root>/active/mime), reached through the active symlink.
	// The mime installer links the host mime packages dir to
	// <ActiveMimeDir>/<file>.
	ActiveMimeDir() string
	// ActiveManDir returns the absolute path of the active generation's shared
	// man directory (<root>/active/man), resolved through the top-level "active"
	// symlink. It exists iff an alternatives man follower placed a man page in the
	// active generation; CLI commands stat it to gate the $MANPATH nudge.
	ActiveManDir() string
}
