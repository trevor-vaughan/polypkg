package importer

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// stagingPrefix starts the name of the directory an import builds its
	// output in. It lives inside out-dir so the final renames stay on one
	// filesystem; an interrupted import leaves it behind, safe to delete.
	stagingPrefix = ".polypkg-import-"
	// trustedRootFile is the Sigstore trusted root an import writes at the top
	// of out-dir.
	trustedRootFile = "sigstore-trusted-root.json"
)

// output stages one import's package sources inside out-dir and commits them
// together, so a failed import leaves out-dir as it was. Every operation goes
// through an os.Root confined to out-dir, so no symlink can redirect a write
// outside it.
type output struct {
	dir     string   // out-dir as the caller named it
	root    *os.Root // confined to dir
	created bool     // openOutput created dir
	staging string   // the staging directory, relative to dir
}

// stagedFile is one file of a staged package source.
type stagedFile struct {
	name string // slash path relative to the package source
	data []byte
	mode fs.FileMode
}

// openOutput opens out-dir, creating it (but not its parent) when missing,
// and makes a fresh staging directory inside it.
func openOutput(dir string) (*output, error) {
	created := true
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // G301: package sources are published; 0755 is intended
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
		created = false
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		if created {
			err = errors.Join(err, os.Remove(dir))
		}
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	o := &output{dir: dir, root: r, created: created, staging: stagingPrefix + rand.Text()}
	if err := r.Mkdir(o.staging, 0o700); err != nil {
		return nil, errors.Join(fmt.Errorf("create a staging directory in %s: %w", dir, err), o.discard())
	}
	return o, nil
}

// stage writes one platform's package source to <staging>/<target>: the
// recipe as polypkg.yaml, the asset as content/<asset> with exactly
// assetMode, and each bundle as attestations/<n>.json, numbered from 1. It
// returns the staged directory's path.
func (o *output) stage(target string, recipe []byte, asset string, data []byte, assetMode fs.FileMode, bundles [][]byte) (string, error) {
	dir := path.Join(o.staging, target)
	files := make([]stagedFile, 0, 2+len(bundles))
	files = append(files, stagedFile{"polypkg.yaml", recipe, 0o644}, stagedFile{"content/" + asset, data, assetMode})
	for i, b := range bundles {
		files = append(files, stagedFile{"attestations/" + strconv.Itoa(i+1) + ".json", b, 0o644})
	}
	for _, f := range files {
		name := filepath.FromSlash(path.Join(dir, f.name))
		if err := o.root.MkdirAll(filepath.Dir(name), 0o755); err != nil { //nolint:gosec // G301: package sources are published; 0755 is intended
			return "", fmt.Errorf("stage %s: %w", f.name, err)
		}
		if err := o.root.WriteFile(name, f.data, f.mode); err != nil { //nolint:gosec // G306: published package files are world-readable by design
			return "", fmt.Errorf("stage %s: %w", f.name, err)
		}
		// WriteFile's mode is filtered by the umask; Chmod sets it exactly.
		if err := o.root.Chmod(name, f.mode); err != nil {
			return "", fmt.Errorf("stage %s: %w", f.name, err)
		}
	}
	return filepath.Join(o.dir, filepath.FromSlash(dir)), nil
}

// commit moves each staged target (a slash path relative to out-dir) into
// place, refusing one that already exists, then writes trustedRoot to
// out-dir/sigstore-trusted-root.json, replacing any earlier one in a single
// rename. On any failure, a panic included, it removes every directory it
// moved in or created, so out-dir is left as it was; a panic then carries
// on unwinding.
func (o *output) commit(targets []string, trustedRoot []byte) (err error) {
	// made holds the directories commit created or moved in, oldest first: at
	// most two parents and the target itself per target.
	made := make([]string, 0, 3*len(targets))
	committed := false
	defer func() {
		if committed {
			return
		}
		errs := []error{err}
		for i := len(made) - 1; i >= 0; i-- {
			if rerr := o.root.RemoveAll(made[i]); rerr != nil {
				errs = append(errs, fmt.Errorf("undo %s: %w", filepath.Join(o.dir, made[i]), rerr))
			}
		}
		err = errors.Join(errs...)
	}()
	for _, t := range targets {
		for _, d := range parents(t) {
			err := o.root.Mkdir(d, 0o755) //nolint:gosec // G301: package sources are published; 0755 is intended
			switch {
			case err == nil:
				made = append(made, d)
			case !errors.Is(err, fs.ErrExist):
				return fmt.Errorf("create %s: %w", filepath.Join(o.dir, d), err)
			}
		}
		final := filepath.Join(o.dir, filepath.FromSlash(t))
		switch _, err := o.root.Lstat(t); {
		case err == nil:
			return fmt.Errorf("%s already exists; refusing to overwrite it", final)
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("check %s: %w", final, err)
		}
		if err := o.root.Rename(path.Join(o.staging, t), t); err != nil {
			return fmt.Errorf("move %s into place: %w", final, err)
		}
		made = append(made, t)
	}
	staged := path.Join(o.staging, trustedRootFile)
	if err := o.root.WriteFile(staged, trustedRoot, 0o644); err != nil { //nolint:gosec // G306: the trusted root is public
		return fmt.Errorf("write %s: %w", trustedRootFile, err)
	}
	if err := o.root.Rename(staged, trustedRootFile); err != nil {
		return fmt.Errorf("move %s into place: %w", filepath.Join(o.dir, trustedRootFile), err)
	}
	committed = true
	return nil
}

// close removes the staging directory and closes out-dir.
func (o *output) close() error {
	return errors.Join(o.root.RemoveAll(o.staging), o.root.Close())
}

// discard undoes everything openOutput and stage did: it closes, and removes
// out-dir itself when openOutput created it.
func (o *output) discard() error {
	err := o.close()
	if o.created {
		err = errors.Join(err, os.Remove(o.dir))
	}
	return err
}

// parents returns the ancestors of the slash path t, outermost first:
// "a/b/c" gives "a" and "a/b".
func parents(t string) []string {
	out := make([]string, 0, strings.Count(t, "/"))
	for i := range len(t) {
		if t[i] == '/' {
			out = append(out, t[:i])
		}
	}
	return out
}
