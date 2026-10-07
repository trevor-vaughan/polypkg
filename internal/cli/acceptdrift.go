package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/drift"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newAcceptDriftCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "accept-drift <path>...",
		Short: "Adopt the live state of one or more managed paths as the new baseline",
		Long: "A managed file is \"drifted\" when its on-disk content has changed since the generation " +
			"that placed it was applied. accept-drift records the current on-disk state as the new expected " +
			"baseline so the next apply stops reporting it as drift.\n\n" +
			"Each named path's current observed state is written to a state-home overrides file so the next " +
			"apply's drift check treats it as not-drifted (while it still matches). The record is keyed by " +
			"the current generation; a new generation invalidates all prior acceptances.\n\n" +
			"`polypkg status -vv` lists the drifted paths.",
		Example: "  # See which managed paths have drifted\n" +
			"  polypkg status -vv\n\n" +
			"  # Adopt the current on-disk state of a path as the new baseline\n" +
			"  polypkg accept-drift ~/.config/foo/bar.conf",
		Args: needsArgs(1, -1, "at least one <path>"),
		RunE: runAcceptDrift,
	}
}

func runAcceptDrift(cmd *cobra.Command, requestedPaths []string) error {
	format, ferr := resolveFormat(cmd)
	if ferr != nil {
		return ferr
	}
	return WrapError(cmd, format, "accept-drift", runAcceptDriftInner(cmd, requestedPaths, format))
}

func runAcceptDriftInner(cmd *cobra.Command, requestedPaths []string, format Format) error {
	ctx := cmd.Context()
	sub, stateHome, err := openUserStore()
	if err != nil {
		return err
	}

	// Take the lock BEFORE reading CurrentOwnership so a concurrent apply
	// cannot commit a new generation under us; otherwise we would write an
	// accepted-drift record keyed to a stale generation that the next apply
	// would silently discard.
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "accept-drift", Command: "polypkg accept-drift"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	prior, gen, activeRoot, err := sub.CurrentOwnership()
	if err != nil {
		return &CLIError{
			Msg:  "no generation has been applied yet",
			Hint: "run `polypkg apply` first",
			Err:  err,
		}
	}

	outPath := filepath.Join(stateHome, "accepted-drift.json")
	if err := writeAcceptedDrift(outPath, gen, activeRoot, prior, requestedPaths); err != nil {
		return err
	}
	EmitResult(cmd, format, "accept-drift", map[string]any{
		"paths_accepted": len(requestedPaths),
		"gen_id":         gen,
	}, func(w *bytes.Buffer, d map[string]any) {
		fmt.Fprintf(w, "accepted drift for %d path(s) in generation %d\n", d["paths_accepted"], d["gen_id"])
	})
	return nil
}

// writeAcceptedDrift validates each requested path against the prior ownership
// index, captures the live state of each from activeRoot (including a fresh
// content hash for install entries and extracted regular files, so a
// content-drift refusal can be accepted), and writes a merged polypkg.accepted-drift/v1 record at outPath.
// If outPath already exists for the same generation, its entries are merged
// with the new ones; a stale (different generation) record is overwritten.
func writeAcceptedDrift(outPath string, gen int, activeRoot string, prior *schema.Ownership, requestedPaths []string) error {
	managed := map[string]schema.OwnershipEntry{}
	for i := range prior.Entries {
		managed[prior.Entries[i].Path] = prior.Entries[i]
	}

	record := &schema.AcceptedDrift{
		Schema:     "polypkg.accepted-drift/v1",
		Generation: gen,
		Paths:      map[string]schema.AcceptedPath{},
	}
	if existing, err := readAcceptedDrift(outPath); err == nil && existing != nil && existing.Generation == gen {
		for k := range existing.Paths {
			record.Paths[k] = existing.Paths[k]
		}
	}

	root, err := os.OpenRoot(activeRoot)
	if err != nil {
		return fmt.Errorf("open active root: %w", err)
	}
	defer func() { _ = root.Close() }()

	for _, p := range requestedPaths {
		owned, ok := managed[p]
		if !ok {
			return &CLIError{
				Msg:  fmt.Sprintf("%s is not a managed path in the current generation", p),
				Hint: "run `polypkg status -vv` to list managed paths with drift",
			}
		}
		info, err := root.Lstat(p)
		if err != nil {
			return fmt.Errorf("lstat %q: %w", p, err)
		}
		ap := schema.AcceptedPath{Stat: schema.StatInfoFrom(info)}
		fileType := fileTypeOf(info)
		switch fileType {
		case "symlink":
			target, err := root.Readlink(p)
			if err != nil {
				return fmt.Errorf("readlink %q: %w", p, err)
			}
			ap.Expected = schema.Expected{FileType: "symlink", Target: target}
		case "dir":
			ap.Expected = schema.Expected{FileType: "dir", Mode: fmt.Sprintf("%#o", info.Mode().Perm())}
		default: // regular
			ap.Expected = schema.Expected{FileType: "regular", Mode: fmt.Sprintf("%#o", info.Mode().Perm())}
		}
		// For install entries and the regular files an extract placed, also
		// capture the live content hash so a ReasonContent drift can be
		// accepted. Directories, symlinks and perms entries do not drift on
		// content, so they do not need it.
		if owned.Action == "install" || (owned.Action == "extract" && fileType == "regular") {
			hash, err := drift.HashLiveContent(root, p, fileType)
			if err != nil {
				return fmt.Errorf("hash %q: %w", p, err)
			}
			ap.Expected.ContentHash = hash
		}
		record.Paths[p] = ap
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal accepted-drift: %w", err)
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, outPath)
}

func readAcceptedDrift(path string) (*schema.AcceptedDrift, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	a, err := schema.ParseAcceptedDrift(f)
	return a, schema.WithPath(err, path)
}

func fileTypeOf(info os.FileInfo) string {
	m := info.Mode()
	switch {
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	default:
		return "regular"
	}
}
