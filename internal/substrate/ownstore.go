package substrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// compile-time assertion that OwnStore implements Substrate.
var _ Substrate = (*OwnStore)(nil)

// OwnStore is polypkg's content-addressed substrate. Generations live
// under <root>/generations/<n>/; the live profile is the
// <root>/active symlink.
type OwnStore struct {
	root    string
	pending map[string]int // tx_id -> staged gen_id
	dirMode os.FileMode    // write-path MkdirAll mode; 0 => 0o700 (see dirPerm)
	// fsync flushes one open file or directory to stable storage. It is
	// (*os.File).Sync in production; tests replace it to observe the order of
	// the commit protocol's durability barriers, which a crash test cannot.
	fsync func(*os.File) error
	// syncfs flushes the filesystem holding an open file (syncfs(2) on
	// Linux). A seam for the same reason as fsync: tests record and fail it.
	syncfs func(*os.File) error
}

// NewOwnStore opens an own-store substrate at root. Opening has no filesystem
// side effects: the substrate's subdirectories (generations/, state/,
// alternatives/) are created lazily by the operations that write into them
// (BeginTransaction, the state action, alternatives materialize), so a read-only
// command on a never-applied store creates nothing and reports "no generation".
func NewOwnStore(root string, opts ...Option) (*OwnStore, error) {
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}
	return &OwnStore{root: root, pending: map[string]int{}, dirMode: cfg.dirMode, fsync: (*os.File).Sync, syncfs: defaultSyncfs}, nil
}

// dirPerm returns the effective directory-creation mode: the configured
// dirMode, or 0o700 when unset (the user-private default).
func (s *OwnStore) dirPerm() os.FileMode {
	if s.dirMode == 0 {
		return 0o700
	}
	return s.dirMode
}

// BeginTransaction stages a new generation for this transaction. It also
// creates the generation's active subdirectory so actions can populate it
// before the commit symlink swap.
func (s *OwnStore) BeginTransaction(txID string) error {
	if _, ok := s.pending[txID]; ok {
		return fmt.Errorf("transaction %q already begun", txID)
	}
	next, err := s.nextGenID()
	if err != nil {
		return fmt.Errorf("compute next gen_id: %w", err)
	}
	stagingDir := filepath.Join(s.root, "generations", strconv.Itoa(next))
	if err := os.MkdirAll(stagingDir, s.dirPerm()); err != nil {
		return fmt.Errorf("mkdir staging: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(stagingDir, "active"), s.dirPerm()); err != nil {
		return fmt.Errorf("mkdir staging active: %w", err)
	}
	s.pending[txID] = next
	return nil
}

// StagingRoot returns <root>/generations/<gen>/active for the pending tx.
// Actions populate this directory; CommitGeneration atomically makes it the
// live active root via a symlink swap.
func (s *OwnStore) StagingRoot(txID string) (string, error) {
	gen, ok := s.pending[txID]
	if !ok {
		return "", fmt.Errorf("transaction %q not begun", txID)
	}
	return filepath.Join(s.root, "generations", strconv.Itoa(gen), "active"), nil
}

// CommitGeneration makes the staged generation durable and then atomically
// swaps the active symlink to it.
//
// Durability order (each step is fsynced before the next begins, so a power
// loss at any point leaves either the previous generation active or this one
// complete and active):
//
//  1. ownership.json and every config-base snapshot, then their directories,
//     the package payload under active/ (syncfs on Linux, a per-file walk
//     elsewhere), and the generation directory;
//  2. manifest.json, the generation's completeness marker, written last so a
//     readable manifest implies everything above is on disk; then the
//     generation directory, generations/, and the store root;
//  3. the active symlink swap, then the store root again (in swapActive).
func (s *OwnStore) CommitGeneration(txID string, m *schema.Manifest, own *schema.Ownership, configBases map[string][]byte) (int, error) {
	gen, ok := s.pending[txID]
	if !ok {
		return 0, fmt.Errorf("transaction %q not begun", txID)
	}
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(gen))
	if err := s.writeOwnership(filepath.Join(genDir, "ownership.json"), m.Scope, own); err != nil {
		return 0, fmt.Errorf("write ownership: %w", err)
	}
	if err := s.writeConfigBases(genDir, configBases); err != nil {
		return 0, fmt.Errorf("write config-base: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(genDir, "active"), s.dirPerm()); err != nil {
		return 0, fmt.Errorf("mkdir active subdir: %w", err)
	}
	// The payload actions placed under active/ must be durable before the
	// manifest, the completeness marker, vouches for this generation.
	if err := s.syncPayload(filepath.Join(genDir, "active")); err != nil {
		return 0, fmt.Errorf("sync package payload: %w", err)
	}
	if err := s.syncDir(genDir); err != nil {
		return 0, err
	}
	if err := s.writeManifest(filepath.Join(genDir, "manifest.json"), gen, m); err != nil {
		return 0, fmt.Errorf("write manifest: %w", err)
	}
	for _, dir := range []string{genDir, filepath.Join(s.root, "generations"), s.root} {
		if err := s.syncDir(dir); err != nil {
			return 0, err
		}
	}
	activeTarget := filepath.Join("generations", strconv.Itoa(gen), "active")
	if err := s.swapActive(activeTarget); err != nil {
		return 0, fmt.Errorf("swap active symlink: %w", err)
	}
	// The atomic swap has succeeded, so the transaction is irrevocably
	// committed. Drop it from pending FIRST: a later Abort of this txID must be
	// a no-op and must never RemoveAll the now-live generation directory.
	delete(s.pending, txID)
	return gen, nil
}

// Abort discards the staged generation for this transaction.
func (s *OwnStore) Abort(txID string) error {
	gen, ok := s.pending[txID]
	if !ok {
		return nil
	}
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(gen))
	if err := s.removeGenerationDir(genDir); err != nil {
		return fmt.Errorf("remove staged: %w", err)
	}
	delete(s.pending, txID)
	return nil
}

// removeGenerationDir deletes a generation directory so that an interruption
// at any point leaves it incomplete. os.RemoveAll is not atomic: cut short, it
// could leave manifest.json over a half-deleted payload, which would look
// complete. So the manifest, the completeness marker, is removed and that
// removal fsynced before anything else is deleted. A directory that no longer
// exists is already removed.
func (s *OwnStore) removeGenerationDir(genDir string) error {
	if err := os.Remove(filepath.Join(genDir, "manifest.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("invalidate manifest: %w", err)
	}
	if err := s.syncDir(genDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.RemoveAll(genDir)
}

// Rollback atomically swaps the active symlink to the named generation. It
// refuses a generation without a readable manifest (ErrIncompleteGeneration):
// the manifest is the completeness marker CommitGeneration writes last.
func (s *OwnStore) Rollback(genID int) error {
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(genID))
	if _, err := os.Stat(genDir); err != nil {
		return fmt.Errorf("target generation: %w", err)
	}
	if _, err := s.ReadManifest(genID); err != nil {
		return fmt.Errorf("target generation %d: %w", genID, err)
	}
	activeTarget := filepath.Join("generations", strconv.Itoa(genID), "active")
	if err := s.swapActive(activeTarget); err != nil {
		return fmt.Errorf("swap active symlink: %w", err)
	}
	return nil
}

// CurrentGeneration returns the active generation ID, derived from the
// authoritative <root>/active symlink. The symlink is updated by an atomic
// rename in swapActive, so it always names the live generation; there is no
// advisory cache to fall stale (a stale cache could make GC delete the live
// generation).
func (s *OwnStore) CurrentGeneration() (int, error) {
	target, err := os.Readlink(filepath.Join(s.root, "active"))
	if err != nil {
		return 0, fmt.Errorf("read active symlink: %w", err)
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) < 2 || parts[0] != "generations" {
		return 0, fmt.Errorf("unexpected active symlink target %q", target)
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("parse generation from active target %q: %w", target, err)
	}
	return n, nil
}

func (s *OwnStore) nextGenID() (int, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "generations"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("read generations: %w", err)
	}
	// A missing generations/ dir means no generations yet (never applied);
	// entries is nil, so the loop below leaves maxGen at 0 and the next id is 1.
	maxGen := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if n > maxGen {
			maxGen = n
		}
	}
	for _, p := range s.pending {
		if p > maxGen {
			maxGen = p
		}
	}
	return maxGen + 1, nil
}

// swapActive atomically points <root>/active at target (a path relative to
// root) using a temp symlink plus rename, which is atomic on POSIX filesystems
// and so never leaves the active pointer in a torn state. It then fsyncs the
// root so the new pointer survives power loss. A failure of that last fsync is
// logged, not returned: the rename is already visible and cannot be undone, and
// reporting failure would make callers treat a live generation as aborted. The
// worst case is that a power loss reverts active to the previous generation,
// which is itself durable.
func (s *OwnStore) swapActive(target string) error {
	activeLink := filepath.Join(s.root, "active")
	tmpLink := activeLink + ".tmp"
	if err := os.Remove(tmpLink); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale tmp symlink: %w", err)
	}
	if err := os.Symlink(target, tmpLink); err != nil {
		return fmt.Errorf("create tmp symlink: %w", err)
	}
	if err := os.Rename(tmpLink, activeLink); err != nil {
		return fmt.Errorf("rename symlink: %w", err)
	}
	if err := s.syncDir(s.root); err != nil {
		slog.Warn("active pointer switched but syncing the store root failed; the switch may not survive a power loss",
			"target", target, "error", err)
	}
	return nil
}

// writeFileDurable writes data to path through a sibling temp file that is
// fsynced before it is renamed over path, so path never names a file whose
// bytes are not on stable storage. The rename itself becomes durable only when
// the caller fsyncs path's directory (syncDir).
func (s *OwnStore) writeFileDurable(path string, data []byte) error {
	tmp := filepath.Clean(path + ".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write tmp: %w", err), f.Close())
	}
	if err := s.fsync(f); err != nil {
		return errors.Join(fmt.Errorf("sync tmp: %w", err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// syncDir fsyncs a directory so the entries created or renamed in it survive a
// power loss.
func (s *OwnStore) syncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("open %s for sync: %w", dir, err)
	}
	if err := s.fsync(d); err != nil {
		return errors.Join(fmt.Errorf("sync %s: %w", dir, err), d.Close())
	}
	return d.Close()
}

// writeConfigBases durably persists each content-addressed config-base
// snapshot under <genDir>/config-base/. Bytes are keyed by their source hash;
// identical bytes across paths/packages map to one file (content-addressed
// dedup within the generation). Every fan-out directory and config-base/ itself
// are fsynced after the files; the caller fsyncs genDir. A nil/empty map is a
// no-op.
func (s *OwnStore) writeConfigBases(genDir string, bases map[string][]byte) error {
	if len(bases) == 0 {
		return nil
	}
	fanout := map[string]bool{}
	for hash, content := range bases {
		rel := schema.ConfigBaseRelPath(hash)
		dest := filepath.Join(genDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(rel), err)
		}
		if err := s.writeFileDurable(dest, content); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		fanout[filepath.Dir(dest)] = true
	}
	dirs := make([]string, 0, len(fanout))
	for dir := range fanout {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range append(dirs, filepath.Join(genDir, "config-base")) {
		if err := s.syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// writeOwnership atomically writes the generation's ownership index. A nil index
// (or one with nil Entries) is normalized to a valid empty document so the file
// always round-trips through schema.ParseOwnership.
func (s *OwnStore) writeOwnership(path, scope string, own *schema.Ownership) error {
	if own == nil {
		own = &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: scope}
	}
	if own.Entries == nil {
		own.Entries = []schema.OwnershipEntry{}
	}
	data, err := json.MarshalIndent(own, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return s.writeFileDurable(path, data)
}

// StateRoot returns <root>/state, the stable state area.
func (s *OwnStore) StateRoot() string {
	return filepath.Join(s.root, "state")
}

// AltRoot returns the absolute path of the stable alternatives area
// (<root>/alternatives), a sibling of generations/ and state/ that is never
// touched by the swap, GC, or rollback. It holds the alternatives action's
// mutable "middle" links (<altRoot>/<name> -> the winning provider's source).
func (s *OwnStore) AltRoot() string {
	return filepath.Join(s.root, "alternatives")
}

// ActiveBinDir returns the absolute path of the shared bin directory of the
// live active generation (<root>/active/bin), resolved through the top-level
// "active" symlink so it stays valid across atomic swaps. The bridge links
// ~/.local/bin entries to <ActiveBinDir>/<name>.
func (s *OwnStore) ActiveBinDir() string {
	return filepath.Join(s.root, "active", "bin")
}

// ActiveCompletionsDir returns the absolute path of the shared completions
// directory of the live active generation (<root>/active/completions), resolved
// through the top-level "active" symlink so it stays valid across atomic swaps.
// The completion installer links host shell dirs to <ActiveCompletionsDir>/<shell>/<file>.
func (s *OwnStore) ActiveCompletionsDir() string {
	return filepath.Join(s.root, "active", "completions")
}

// ActiveDesktopDir returns the absolute path of the shared applications
// directory of the live active generation (<root>/active/applications),
// resolved through the top-level "active" symlink so it stays valid across
// atomic swaps. The desktop installer links host applications dirs to
// <ActiveDesktopDir>/<file>.
func (s *OwnStore) ActiveDesktopDir() string {
	return filepath.Join(s.root, "active", "applications")
}

// ActiveMimeDir returns the absolute path of the shared mime directory of the
// live active generation (<root>/active/mime), resolved through the top-level
// "active" symlink so it stays valid across atomic swaps. The mime installer
// links the host mime packages dir to <ActiveMimeDir>/<file>.
func (s *OwnStore) ActiveMimeDir() string {
	return filepath.Join(s.root, "active", "mime")
}

// ActiveManDir returns the absolute path of the shared man directory of the live
// active generation (<root>/active/man), resolved through the top-level "active"
// symlink so it stays valid across atomic swaps. It exists iff an alternatives
// man follower has placed a man page in the active generation; CLI commands stat
// it to decide whether to emit the $MANPATH nudge.
func (s *OwnStore) ActiveManDir() string {
	return filepath.Join(s.root, "active", "man")
}

// PurgeState removes <root>/state/<pkg> recursively. Idempotent.
// pkg must be a single path component (no separators, not "."/".."): this
// guards a destructive os.RemoveAll against path traversal that could escape
// the state area and delete generations or the whole substrate.
func (s *OwnStore) PurgeState(pkg string) error {
	if pkg == "" || pkg == "." || pkg == ".." || pkg != filepath.Base(pkg) {
		return fmt.Errorf("purge state: invalid package name %q", pkg)
	}
	if err := os.RemoveAll(filepath.Join(s.root, "state", pkg)); err != nil {
		return fmt.Errorf("purge state %q: %w", pkg, err)
	}
	return nil
}

// CurrentOwnership reads the current generation's ownership.json and returns
// it together with its generation ID and the absolute path of
// generations/<n>/active. Returns ErrNoCurrentGeneration when no generation
// has been committed yet.
func (s *OwnStore) CurrentOwnership() (own *schema.Ownership, gen int, activeRoot string, err error) {
	gen, err = s.CurrentGeneration()
	if err != nil {
		// The active symlink only exists post-commit; any unresolved-current is
		// reported as "no current generation" so callers can detect first-apply.
		return nil, 0, "", ErrNoCurrentGeneration
	}
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(gen))
	ownPath := filepath.Join(genDir, "ownership.json")
	f, err := os.Open(filepath.Clean(ownPath))
	if err != nil {
		return nil, 0, "", fmt.Errorf("open ownership.json: %w", err)
	}
	defer func() { _ = f.Close() }()
	own, err = schema.ParseOwnership(f)
	if err != nil {
		return nil, 0, "", fmt.Errorf("parse ownership.json: %w", schema.WithPath(err, ownPath))
	}
	return own, gen, filepath.Join(genDir, "active"), nil
}

// writeManifest durably writes the manifest of generation gen. The written copy
// records gen as its Generation, so ReadManifest can tell a manifest that sits
// in another generation's directory from the one CommitGeneration wrote there.
// A nil Entries slice is written as an empty array: the manifest is the
// generation's completeness marker, so what CommitGeneration writes must always
// pass schema.ParseManifest (the schema rejects "entries": null). The caller's
// manifest is not mutated.
func (s *OwnStore) writeManifest(path string, gen int, m *schema.Manifest) error {
	stamped := *m
	stamped.Generation = gen
	if stamped.Entries == nil {
		stamped.Entries = []schema.ManifestEntry{}
	}
	data, err := json.MarshalIndent(&stamped, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return s.writeFileDurable(path, data)
}

// ListGenerations enumerates every retained generation directory under
// <root>/generations/, parses each generation's manifest and (optional)
// pin.json, marks the currently active one, and computes a best-effort
// recursive size for BytesOnDisk. A generation with no manifest is reported
// with Incomplete set, and one whose manifest is present but unusable with
// Damaged set; both have a zero CommittedAt and neither aborts the listing,
// because GC needs the complete picture. Any other failure to read a manifest
// (EACCES, EIO, EMFILE, or a manifest a newer polypkg wrote) aborts the listing
// with an error: it says nothing this binary can judge about the generation,
// and guessing a state could let GC delete a valid one.
func (s *OwnStore) ListGenerations() ([]GenInfo, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "generations"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read generations: %w", err)
	}
	// A missing generations/ dir lists as empty (never applied); entries is nil.
	current, _ := s.CurrentGeneration() // zero is fine for first-apply

	out := make([]GenInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // ignore non-numeric entries (defensive)
		}
		info := GenInfo{ID: id, IsCurrent: id == current}

		genDir := filepath.Join(s.root, "generations", strconv.Itoa(id))

		m, merr := s.ReadManifest(id)
		switch {
		case merr == nil:
			info.CommittedAt = m.ProducedBy.Timestamp
		case errors.Is(merr, ErrIncompleteGeneration):
			info.Incomplete = true
		case errors.Is(merr, ErrDamagedGeneration):
			info.Damaged = true
			slog.Warn("ListGenerations: generation manifest is damaged; keeping it for inspection",
				"gen", id, "error", merr)
		default:
			return nil, merr
		}

		pPath := filepath.Join(genDir, "pin.json")
		if pf, err := os.Open(filepath.Clean(pPath)); err == nil {
			p, perr := schema.ParsePin(pf)
			_ = pf.Close()
			var newer *schema.NewerSchemaError
			switch {
			case perr == nil:
				info.Pinned = true
				info.PinnedReason = p.PinnedReason
			case errors.As(perr, &newer):
				// A newer polypkg pinned this generation. Honour the pin
				// rather than let this older binary's gc collect it.
				info.Pinned = true
				slog.Warn("ListGenerations: pin.json written by a newer polypkg; treating as pinned",
					"gen", id, "error", schema.WithPath(perr, pPath))
			default:
				slog.Warn("ListGenerations: pin.json parse failed; treating as unpinned",
					"gen", id, "error", perr)
			}
		}

		info.BytesOnDisk = dirSize(genDir)
		out = append(out, info)
	}
	return out, nil
}

// ReadManifest parses generations/<id>/manifest.json. The error wraps
// ErrIncompleteGeneration when the manifest is missing: CommitGeneration writes
// it last, so this directory was never completed. It wraps ErrDamagedGeneration
// when the bytes do not parse or record a generation other than id: a crash
// cannot cause either (the manifest is renamed into place only after it is
// fsynced, and stamped with its own id), so they mean corruption or tampering.
// A Generation of 0 is accepted as the unstamped manifest of an older binary.
// A manifest a newer polypkg wrote is returned as a *schema.NewerSchemaError
// naming its path, without either wrap: it is neither interrupted nor
// corrupt, this binary just cannot judge it, so callers must neither delete
// it as incomplete nor send the operator to delete it as damaged. Any other
// read failure (EACCES, EIO, EMFILE) is likewise returned without either
// wrap, because it says nothing about the generation.
func (s *OwnStore) ReadManifest(id int) (*schema.Manifest, error) {
	mPath := filepath.Join(s.root, "generations", strconv.Itoa(id), "manifest.json")
	data, err := os.ReadFile(filepath.Clean(mPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read manifest for generation %d: %w: %w", id, ErrIncompleteGeneration, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest for generation %d: %w", id, err)
	}
	m, err := schema.ParseManifest(bytes.NewReader(data))
	var newer *schema.NewerSchemaError
	if errors.As(err, &newer) {
		return nil, fmt.Errorf("parse manifest for generation %d: %w", id, schema.WithPath(err, mPath))
	}
	if err != nil {
		return nil, fmt.Errorf("parse manifest for generation %d: %w: %w", id, ErrDamagedGeneration, err)
	}
	if m.Generation != 0 && m.Generation != id {
		return nil, fmt.Errorf("manifest for generation %d records generation %d: %w", id, m.Generation, ErrDamagedGeneration)
	}
	return m, nil
}

// GenerationIDs enumerates retained generation IDs from the directory names
// under <root>/generations/. Unlike ListGenerations it parses nothing and
// sizes nothing — the ID is the directory name — so callers that need only the
// ID set avoid a wasted manifest+pin parse and recursive size walk per
// generation. Order is unspecified; callers sort. A missing generations/ dir
// (never applied) enumerates as empty.
func (s *OwnStore) GenerationIDs() ([]int, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "generations"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read generations: %w", err)
	}
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, aerr := strconv.Atoi(e.Name())
		if aerr != nil {
			continue // ignore non-numeric entries (defensive)
		}
		out = append(out, id)
	}
	return out, nil
}

// dirSize walks dir recursively and returns the sum of regular-file sizes
// it observes. A walk error returns whatever was summed so far; callers
// treat the result as advisory.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort: continue past unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// PinGeneration writes the per-generation pin.json with the given reason.
// PinnedBy is $USER or "unknown". Errors if the generation does not exist,
// is incomplete or damaged (wrapping ErrIncompleteGeneration or
// ErrDamagedGeneration), or is already pinned
// (callers must Unpin first to change a reason).
func (s *OwnStore) PinGeneration(id int, reason string) error {
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(id))
	if _, err := os.Stat(genDir); err != nil {
		return fmt.Errorf("pin generation %d: %w", id, err)
	}
	// A pin marks a generation as a rollback target to keep. An incomplete or
	// damaged one can never be activated, so pinning it would be meaningless.
	if _, err := s.ReadManifest(id); err != nil {
		return fmt.Errorf("pin generation %d: %w", id, err)
	}
	pinPath := filepath.Join(genDir, "pin.json")
	if _, err := os.Stat(pinPath); err == nil {
		return fmt.Errorf("pin generation %d: already pinned", id)
	}

	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}

	p := &schema.Pin{
		Schema:       "polypkg.pin/v1",
		Generation:   id,
		PinnedAt:     time.Now().UTC(),
		PinnedBy:     user,
		PinnedReason: reason,
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("pin generation %d: marshal: %w", id, err)
	}
	tmp := pinPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("pin generation %d: write tmp: %w", id, err)
	}
	if err := os.Rename(tmp, pinPath); err != nil {
		return fmt.Errorf("pin generation %d: rename: %w", id, err)
	}
	return nil
}

// UnpinGeneration removes the per-generation pin.json. It is idempotent: a
// no-op when the generation is not pinned (mirrors `rm -f`). Errors if the
// generation directory does not exist (callers passed a bad gen id).
func (s *OwnStore) UnpinGeneration(id int) error {
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(id))
	if _, err := os.Stat(genDir); err != nil {
		return fmt.Errorf("unpin generation %d: %w", id, err)
	}
	pinPath := filepath.Join(genDir, "pin.json")
	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unpin generation %d: %w", id, err)
	}
	return nil
}

// RemoveGeneration destroys the named generation's storage. It is defensive:
// refuses to delete the currently-active generation (would orphan the active
// symlink) and refuses pinned generations (callers must UnpinGeneration
// first). The gc package's Decide function already filters both cases out;
// this substrate-level guard prevents accidental misuse from CLI scaffolding
// or future callers.
func (s *OwnStore) RemoveGeneration(id int) error {
	genDir := filepath.Join(s.root, "generations", strconv.Itoa(id))
	if _, err := os.Stat(genDir); err != nil {
		return fmt.Errorf("remove generation %d: %w", id, err)
	}
	cur, _ := s.CurrentGeneration()
	if cur == id {
		return fmt.Errorf("remove generation %d: cannot remove the current generation", id)
	}
	pinPath := filepath.Join(genDir, "pin.json")
	if _, err := os.Stat(pinPath); err == nil {
		return fmt.Errorf("remove generation %d: pinned (unpin first or use --force-pin)", id)
	}
	if err := s.removeGenerationDir(genDir); err != nil {
		return fmt.Errorf("remove generation %d: %w", id, err)
	}
	return nil
}
