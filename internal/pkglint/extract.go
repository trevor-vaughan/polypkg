package pkglint

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/archive"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// checkExtract adds the checks the extract action needs beyond its registry
// ParamSpec kinds. PKG010: src must name a file under $PKG/ and dest a
// directory strictly below $ACTIVE/<package name>/ (the only places apply
// lets the action read and write), dest must not be created by an action that
// runs before it, strip_components must pass action.CheckStripComponents, and
// include must be a non-empty list whose patterns pass
// action.CheckIncludePattern; the action runs the same two validators at
// apply time. Values of the wrong kind (a fractional strip_components, a
// non-string include entry) are checkValue's finding and are not reported
// again here. PKG012: a src that exists in the package source must be no
// larger than a package member may be and must start with the magic bytes of
// an archive format apply can unpack. !starlark values are computed at apply
// time and are not checked; a missing param is PKG002's finding and a missing
// src file is PKG006's.
func checkExtract(pkg *schema.Package, idx *docIndex, dir string) []Finding {
	var out []Finding
	for i, v := range pkg.Actions {
		if v.Action != "extract" {
			continue
		}
		add := func(ruleID, param, msg string) {
			out = append(out, Finding{
				RuleID: ruleID, Severity: SeverityError, File: "polypkg.yaml",
				Loc:     loc(idx.paramNode(i, param)),
				Message: fmt.Sprintf("action %q parameter %q %s", v.Action, param, msg),
			})
		}
		if raw, present := v.Params["src"]; present {
			switch s := raw.(type) {
			case schema.StarlarkExpr:
				// computed at apply time
			case string:
				rel, ok := underPrefix(s, "$PKG/")
				if !ok {
					add("PKG010", "src", fmt.Sprintf("value %q must name a file under $PKG/", s))
				} else if problem := archiveProblem(dir, rel); problem != "" {
					add("PKG012", "src", fmt.Sprintf("references %q, %s", rel, problem))
				}
			default:
				add("PKG010", "src", fmt.Sprintf("value %v must be a string", raw))
			}
		}
		if raw, present := v.Params["dest"]; present {
			switch s := raw.(type) {
			case schema.StarlarkExpr:
				// computed at apply time
			case string:
				prefix := "$ACTIVE/" + pkg.Name + "/"
				if rel, ok := underPrefix(s, prefix); !ok {
					add("PKG010", "dest", fmt.Sprintf("value %q must name a directory below $ACTIVE/%s/", s, pkg.Name))
				} else if j, created := createdBefore(pkg, i, prefix+rel); j >= 0 {
					where := fmt.Sprintf("actions[%d]", j)
					if line := loc(idx.actionNode(j)).Line; line > 0 {
						where = fmt.Sprintf("line %d", line)
					}
					add("PKG010", "dest", fmt.Sprintf("value %q already exists when extract runs: the %q action at %s creates %q first, and extract refuses an existing dest",
						s, pkg.Actions[j].Action, where, created))
				}
			default:
				add("PKG010", "dest", fmt.Sprintf("value %v must be a string", raw))
			}
		}
		if raw, present := v.Params["strip_components"]; present {
			_, computed := raw.(schema.StarlarkExpr)
			// A value that is not an integer is checkValue's finding; skip it
			// rather than report the parameter twice.
			isInt := checkValue(action.ParamSpec{Name: "strip_components", Kind: action.KindInt}, raw) == ""
			if !computed && isInt {
				if _, err := action.CheckStripComponents(raw); err != nil {
					add("PKG010", "strip_components", err.Error())
				}
			}
		}
		if list, ok := v.Params["include"].([]any); ok {
			if len(list) == 0 {
				add("PKG010", "include", "is an empty list; omit include to unpack every member")
			}
			for _, e := range list {
				if p, ok := e.(string); ok { // a non-string entry is checkValue's finding
					if err := action.CheckIncludePattern(p); err != nil {
						add("PKG010", "include", err.Error())
					}
				}
			}
		}
	}
	return out
}

// underPrefix reports whether s is prefix followed by a relative path that
// stays strictly below prefix once cleaned, and returns that path cleaned.
// "$PKG/../x", "$PKG/", "$PKG/." and "$PKG/x/.." are all refused.
func underPrefix(s, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok || !filepath.IsLocal(filepath.FromSlash(rest)) {
		return "", false
	}
	rel := path.Clean(rest)
	if rel == "." {
		return "", false
	}
	return rel, true
}

// archiveProblem inspects the src file rel (slash-separated, relative to the
// package source dir) and returns why apply could not unpack it, or "" when
// its leading bytes are an archive format apply supports. A file larger than
// the per-member limit can never install: the artifact extraction that
// precedes every apply refuses it. A missing file
// returns "": PKG006 reports it. A symlink at the file or at any directory
// leading to it is reported without being followed, because repo build
// refuses every symlink in content/ (the extract action itself would follow
// one that stays inside the package). The file is reached through an os.Root
// so lint cannot read outside the package, and it is stat'ed before it is
// opened so a FIFO cannot block lint. Lint does not
// decompress: a compressed stream that holds no tar is apply's to refuse.
func archiveProblem(dir, rel string) string {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Sprintf("which cannot be read: %v", err)
	}
	defer func() { _ = root.Close() }()
	// repo build refuses a symlink anywhere in content/, so lint does too:
	// Lstat each component, the file and every directory leading to it.
	const symlinkRefused = "repo build refuses any symlink in content/, so the package could not be published"
	segs := strings.Split(rel, "/")
	for i := range segs {
		prefix := strings.Join(segs[:i+1], "/")
		info, err := root.Lstat(filepath.FromSlash(prefix))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return ""
		case err != nil:
			return fmt.Sprintf("which cannot be read: %v", err)
		case info.Mode()&fs.ModeSymlink == 0:
			continue
		case i == len(segs)-1:
			return "which is a symlink; " + symlinkRefused
		default:
			return fmt.Sprintf("but %q is a symlink; %s", prefix, symlinkRefused)
		}
	}
	name := filepath.FromSlash(rel)
	info, err := root.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		return fmt.Sprintf("which resolves outside the package or cannot be read: %v", err)
	}
	if !info.Mode().IsRegular() {
		return "which is not a regular file"
	}
	if limit := archive.DefaultLimits().MaxFileBytes; info.Size() > limit {
		return fmt.Sprintf("which is %d bytes; package members are limited to %d GiB, so the package could never install",
			info.Size(), limit>>30)
	}
	f, err := root.Open(name)
	if err != nil {
		return fmt.Sprintf("which cannot be read: %v", err)
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, archive.DetectHeaderLen)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return fmt.Sprintf("which cannot be read: %v", err)
	}
	if _, err := archive.Detect(head[:n]); err != nil {
		return fmt.Sprintf("which apply cannot unpack: %v", err)
	}
	return ""
}

// creatingParam names, per action, the param whose path the action creates
// in the generation (parents included). perms and unmanaged create nothing,
// and the remaining file-placing actions place outside the package directory.
var creatingParam = map[string]string{
	"install": "dest", "symlink": "dest", "config": "dest",
	"dir": "path", "state": "path", "extract": "dest",
}

// createdBefore returns the index of the first action that runs before
// pkg.Actions[i] and creates dest (a cleaned "$ACTIVE/<name>/<rel>" path) or a
// path below it, together with the path it creates; it returns -1 when none
// does. Actions run in action.PhaseRank order, then declaration order within
// a phase. Only literal values are compared.
func createdBefore(pkg *schema.Package, i int, dest string) (at int, created string) {
	rank, ok := action.PhaseRank(pkg.Actions[i].Phase)
	if !ok {
		return -1, ""
	}
	for j, a := range pkg.Actions {
		r, ok := action.PhaseRank(a.Phase)
		if j == i || !ok || r > rank || (r == rank && j > i) {
			continue
		}
		s, ok := a.Params[creatingParam[a.Action]].(string)
		if !ok {
			continue
		}
		if p := path.Clean(s); p == dest || strings.HasPrefix(p, dest+"/") {
			return j, s
		}
	}
	return -1, ""
}
