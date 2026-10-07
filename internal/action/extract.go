package action

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"github.com/trevor-vaughan/polypkg/internal/archive"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// beforeExtractRename, when set, runs after the archive is extracted and
// before the staging directory is renamed to dest. Tests use it to change the
// filesystem in that window.
var beforeExtractRename func()

// extractParams is the validated parameter set of one extract invocation.
type extractParams struct {
	src     string
	dest    string
	strip   int
	include []string
}

// Extract implements the `extract` action: unpack an archive shipped in the
// package's own files (src) into a new directory inside the package's scope
// (dest). The format is detected from the archive's leading bytes, never its
// name, and every entry goes through the strict archive policy, which refuses
// anything that could escape dest or that a release archive has no business
// containing. dest must not exist yet: the archive is extracted into a
// temporary sibling inside the same confined root and renamed into place only
// once every entry succeeded, so a refused archive leaves nothing at dest. It
// returns one Result for dest and one per placed directory, regular file and
// symlink, so each becomes its own ownership entry.
func Extract(inv Invocation, scope Scope) ([]Result, error) {
	p, err := parseExtractParams(inv.Params)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}
	if !scope.AllowsSource(p.src) {
		return nil, fmt.Errorf("extract: src %q is outside the package's files", p.src)
	}
	srcRoot, relSrc, err := scope.openPackage(p.src)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}
	defer func() { _ = srcRoot.Close() }()
	// Check the type before opening: opening a FIFO blocks until a writer
	// appears. Stat follows a symlink only within the package's files.
	srcInfo, err := srcRoot.Stat(relSrc)
	if err != nil {
		return nil, fmt.Errorf("extract: stat src %q: %w", p.src, err)
	}
	if !srcInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("extract: src %q is not a regular file", p.src)
	}
	f, err := srcRoot.Open(relSrc)
	if err != nil {
		return nil, fmt.Errorf("extract: open src %q: %w", p.src, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("extract: stat src %q: %w", p.src, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("extract: src %q is not a regular file", p.src)
	}
	head := make([]byte, archive.DetectHeaderLen)
	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("extract: read src %q: %w", p.src, err)
	}
	format, err := archive.Detect(head[:n])
	if err != nil {
		return nil, fmt.Errorf("extract: src %q: %w", p.src, err)
	}

	root, relDest, err := scope.openScope(p.dest)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}
	defer func() { _ = root.Close() }()
	if relDest == "." {
		return nil, fmt.Errorf("extract: dest %q is the package scope itself; extract into a subdirectory of it", p.dest)
	}
	_, err = root.Lstat(relDest)
	switch {
	case err == nil:
		return nil, fmt.Errorf("extract: dest %q already exists; extract creates its destination directory itself", p.dest)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("extract: check dest %q: %w", p.dest, err)
	}

	opts := archive.Options{
		Format:          format,
		Policy:          archive.PolicyStrict,
		Limits:          archive.DefaultLimits(),
		StripComponents: p.strip,
		Include:         p.include,
		DirPerm:         scope.dirPerm(),
	}
	placed, err := stageExtract(root, relDest, f, info.Size(), opts)
	if err != nil {
		return nil, fmt.Errorf("extract: %s into %s: %w", p.src, p.dest, err)
	}
	destAbs := filepath.Join(scope.ActiveRoot, scope.PackageName, relDest)
	results, err := extractResults(root, destAbs, relDest, placed, opts.DirPerm)
	if err != nil {
		return nil, fmt.Errorf("extract: record %s: %w", p.dest, err)
	}
	return results, nil
}

// CheckStripComponents validates a strip_components value as pkg lint and
// the extract action both read it: a whole number (an int, int64, whole
// float64 or numeric string, the forms YAML, JSONC and !starlark produce) from
// 0 to archive.MaxMemberDepth. A larger value could only strip every member,
// since no member path is deeper. The error omits the parameter name so each
// caller can place it.
func CheckStripComponents(v any) (int, error) {
	notInt := fmt.Errorf("must be a non-negative integer, got %v", v)
	// Range-check in float64 so no conversion to int can overflow first.
	var f float64
	switch t := v.(type) {
	case int:
		f = float64(t)
	case int64:
		f = float64(t)
	case float64:
		if t != math.Trunc(t) { // also true for NaN
			return 0, notInt
		}
		f = t
	case string:
		i, err := strconv.Atoi(t)
		if err != nil {
			return 0, notInt
		}
		f = float64(i)
	default:
		return 0, notInt
	}
	switch {
	case f < 0:
		return 0, notInt
	case f > archive.MaxMemberDepth:
		return 0, fmt.Errorf("must be at most %d, the deepest member path an archive may hold; got %v", archive.MaxMemberDepth, v)
	}
	return int(f), nil
}

// CheckIncludePattern validates one include pattern as pkg lint and the
// extract action both read it: non-empty, since an empty pattern matches no
// member, and well-formed for path.Match, which validates the whole pattern
// even when matching against "". The error omits the parameter name so each
// caller can place it.
func CheckIncludePattern(p string) error {
	if p == "" {
		return errors.New("has an empty pattern, which can match no archive member")
	}
	if _, err := path.Match(p, ""); err != nil {
		return fmt.Errorf("pattern %q is not a valid path.Match pattern: %w", p, err)
	}
	return nil
}

// parseExtractParams validates the extract params: src and dest are required
// strings, strip_components a CheckStripComponents value, include a
// non-empty list of CheckIncludePattern patterns.
func parseExtractParams(params map[string]any) (extractParams, error) {
	var p extractParams
	p.src, _ = params["src"].(string)
	if p.src == "" {
		return p, errors.New("missing required param 'src'")
	}
	p.dest, _ = params["dest"].(string)
	if p.dest == "" {
		return p, errors.New("missing required param 'dest'")
	}
	if raw, ok := params["strip_components"]; ok {
		n, err := CheckStripComponents(raw)
		if err != nil {
			return p, fmt.Errorf("strip_components %w", err)
		}
		p.strip = n
	}
	if raw, ok := params["include"]; ok {
		list, isList := raw.([]any)
		if !isList || len(list) == 0 {
			return p, fmt.Errorf("include must be a non-empty list of path patterns, got %v", raw)
		}
		for _, item := range list {
			pattern, isString := item.(string)
			if !isString {
				return p, fmt.Errorf("include entry %v is not a pattern string", item)
			}
			if err := CheckIncludePattern(pattern); err != nil {
				return p, fmt.Errorf("include %w", err)
			}
			p.include = append(p.include, pattern)
		}
	}
	return p, nil
}

// stageExtract extracts the archive into a new, randomly named directory beside
// relDest inside root, sets that directory to opts.DirPerm (Mkdir honours the
// umask; the strict policy already sets every entry beneath it exactly), then
// renames the directory to relDest. The staging name has a fixed length, so a
// dest name close to the file-name limit still fits.
//
// On any failure, or a panic, the staging directory is removed. Parent
// directories of relDest created here may remain; the runner discards the
// whole staged generation when an action fails.
//
// dest is checked again just before the rename, because rename(2) silently
// replaces an empty directory. That narrows the window but cannot close it:
// polypkg assumes a single writer, which the scope's apply lock and the
// private staged generation provide.
func stageExtract(root *os.Root, relDest string, src io.ReaderAt, size int64, opts archive.Options) (placed []archive.Placed, err error) {
	parent := filepath.Dir(relDest)
	if parent != "." {
		if err = root.MkdirAll(parent, opts.DirPerm); err != nil {
			return nil, fmt.Errorf("create parent of dest: %w", err)
		}
	}
	tmp := filepath.Join(parent, ".extract-"+rand.Text())
	if err = root.Mkdir(tmp, opts.DirPerm); err != nil {
		return nil, fmt.Errorf("create temporary directory: %w", err)
	}
	renamed := false
	defer func() {
		if renamed {
			return
		}
		if rmErr := root.RemoveAll(tmp); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("remove temporary directory %s: %w", tmp, rmErr))
		}
	}()

	tmpRoot, err := root.OpenRoot(tmp)
	if err != nil {
		return nil, fmt.Errorf("open temporary directory: %w", err)
	}
	placed, err = archive.Extract(src, size, tmpRoot, opts)
	if cerr := tmpRoot.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("close temporary directory: %w", cerr)
	}
	if err != nil {
		return nil, err
	}
	if err = root.Chmod(tmp, opts.DirPerm); err != nil {
		return nil, fmt.Errorf("set mode of dest: %w", err)
	}

	if beforeExtractRename != nil {
		beforeExtractRename()
	}
	switch _, lerr := root.Lstat(relDest); {
	case lerr == nil:
		return nil, errors.New("dest already exists: it appeared while the archive was extracted")
	case !errors.Is(lerr, fs.ErrNotExist):
		return nil, fmt.Errorf("check dest: %w", lerr)
	}
	if err = root.Rename(tmp, relDest); err != nil {
		return nil, fmt.Errorf("move into place: %w", err)
	}
	renamed = true
	return placed, nil
}

// extractResults builds the Results for an extracted tree: one for dest, then
// one per placed entry in archive order. Each carries the Expected shape the
// single-path actions record — a directory as dir does, a regular file as
// install (copy) does plus its mode, a symlink as symlink does — so every
// extracted path is tracked like any other managed path.
func extractResults(root *os.Root, destAbs, relDest string, placed []archive.Placed, dirPerm os.FileMode) ([]Result, error) {
	dirMode := fmt.Sprintf("%#o", dirPerm.Perm())
	destStat, err := capturedStat(root, relDest)
	if err != nil {
		return nil, fmt.Errorf("stat dest: %w", err)
	}
	results := make([]Result, 0, len(placed)+1)
	results = append(results, Result{
		Action: "extract", Path: destAbs, Outcome: "ok",
		Expected: schema.Expected{FileType: "dir", Mode: dirMode}, Stat: destStat,
	})
	for i := range placed {
		pl := &placed[i]
		rel := filepath.Join(relDest, filepath.FromSlash(pl.Path))
		var exp schema.Expected
		switch pl.Kind {
		case archive.KindDir:
			exp = schema.Expected{FileType: "dir", Mode: dirMode}
		case archive.KindFile:
			hash, err := hashConfined(root, rel)
			if err != nil {
				return nil, fmt.Errorf("hash %s: %w", pl.Path, err)
			}
			exp = schema.Expected{FileType: "regular", ContentHash: hash, Mode: fmt.Sprintf("%#o", pl.Mode.Perm())}
		case archive.KindSymlink:
			target, err := root.Readlink(rel)
			if err != nil {
				return nil, fmt.Errorf("read link %s: %w", pl.Path, err)
			}
			exp = schema.Expected{FileType: "symlink", Target: target}
		default:
			return nil, fmt.Errorf("archive reported entry %q of unknown kind %q", pl.Path, pl.Kind)
		}
		stat, err := capturedStat(root, rel)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", pl.Path, err)
		}
		results = append(results, Result{
			Action: "extract", Path: filepath.Join(destAbs, filepath.FromSlash(pl.Path)), Outcome: "ok",
			Expected: exp, Stat: stat,
		})
	}
	return results, nil
}
