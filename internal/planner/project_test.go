package planner

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// writeInstallSource creates a package root containing content/bin/hi with the
// given bytes and returns the root. The install/path/alternatives projections
// hash this source identically to the install action, so projection tests need a
// real file on disk.
func writeInstallSource(content string) string {
	root := GinkgoT().TempDir()
	dir := filepath.Join(root, "content", "bin")
	Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "hi"), []byte(content), 0o755)).To(Succeed())
	return root
}

var _ = Describe("ProjectOwnership", func() {
	It("projects an install action with $ACTIVE substitution", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "install",
				Params: map[string]any{
					"src":    "$PKG/content/bin/hi",
					"dest":   "$ACTIVE/hello/bin/hi",
					"policy": "symlink",
				},
			}},
		}
		pkgRoot := writeInstallSource("#!/bin/sh\necho hi\n")
		entries := []runner.RunEntry{{Package: pkg, PkgRoot: pkgRoot}}
		own, err := ProjectOwnership(entries, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("hello/bin/hi"))
		Expect(own.Entries[0].Action).To(Equal("install"))
		Expect(own.Entries[0].Expected.FileType).To(Equal("symlink"))
		// The projected content_hash must equal the hash the install action
		// records, so a converged system does not report false content drift.
		wantHash, herr := action.HashInstallSource(pkgRoot, filepath.Join(pkgRoot, "content", "bin", "hi"))
		Expect(herr).NotTo(HaveOccurred())
		Expect(own.Entries[0].Expected.ContentHash).To(Equal(wantHash))
	})

	It("projects a regular file for an install that omits policy (the copy default)", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "install",
				Params: map[string]any{
					"src":  "$PKG/content/bin/hi",
					"dest": "$ACTIVE/hello/bin/hi",
				},
			}},
		}
		pkgRoot := writeInstallSource("#!/bin/sh\necho hi\n")
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: pkgRoot}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Expected.FileType).To(Equal("regular"),
			"the projection must match what the install action records, or a converged system shows false drift")
	})

	It("projects a different content hash for different install source files", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "install",
				Params: map[string]any{
					"src":    "$PKG/content/bin/hi",
					"dest":   "$ACTIVE/hello/bin/hi",
					"policy": "symlink",
				},
			}},
		}
		// Project with v1 source
		pkgRootV1 := writeInstallSource("#!/bin/sh\necho v1\n")
		entriesV1 := []runner.RunEntry{{Package: pkg, PkgRoot: pkgRootV1}}
		ownV1, err := ProjectOwnership(entriesV1, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(ownV1.Entries).To(HaveLen(1))
		hashV1 := ownV1.Entries[0].Expected.ContentHash
		Expect(hashV1).NotTo(BeEmpty())

		// Project with v2 source
		pkgRootV2 := writeInstallSource("#!/bin/sh\necho v2\n")
		entriesV2 := []runner.RunEntry{{Package: pkg, PkgRoot: pkgRootV2}}
		ownV2, err := ProjectOwnership(entriesV2, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(ownV2.Entries).To(HaveLen(1))
		hashV2 := ownV2.Entries[0].Expected.ContentHash
		Expect(hashV2).NotTo(BeEmpty())

		// Different source files must project different hashes
		Expect(hashV1).NotTo(Equal(hashV2))
	})

	It("projects a symlink action with target preserved", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "symlink",
				Params: map[string]any{
					"src":  "/etc/foo",
					"dest": "$ACTIVE/hello/cfg",
				},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Expected.Target).To(Equal("/etc/foo"))
	})

	It("projects a dir action with mode", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "dir",
				Params: map[string]any{
					"path": "$ACTIVE/hello/bin",
					"mode": "0o755",
				},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Action).To(Equal("dir"))
		// Canonicalized to the runner's "%#o" stored form so plan converges
		// against the apply-time ownership (the literal "0o755" would false-diff).
		Expect(own.Entries[0].Expected.Mode).To(Equal("0755"))
	})

	It("canonicalizes equivalent dir mode literals to the stored form", func() {
		for _, lit := range []string{"0o700", "0700", "700"} {
			pkg := &schema.Package{
				Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
				Actions: []schema.PackageAction{{
					Phase: "post-place", Action: "dir",
					Params: map[string]any{"path": "$ACTIVE/hello/bin", "mode": lit},
				}},
			}
			own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
			Expect(err).NotTo(HaveOccurred())
			Expect(own.Entries[0].Expected.Mode).To(Equal("0700"), "literal %q", lit)
		}
	})

	It("still projects a distinct mode for a real mode change (negative case)", func() {
		// Stored apply-time mode is "0755"; a profile that asks for 0700 must
		// project "0700" so the diff still reports a real ownership change.
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "dir",
				Params: map[string]any{"path": "$ACTIVE/hello/bin", "mode": "0o700"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].Expected.Mode).To(Equal("0700"))
		Expect(own.Entries[0].Expected.Mode).NotTo(Equal("0755"))
	})

	It("projects a perms action with absent mode as empty Expected", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "perms",
				Params: map[string]any{
					"path": "$ACTIVE/hello/bin/hi",
				},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Action).To(Equal("perms"))
		Expect(own.Entries[0].Expected).To(Equal(schema.Expected{}))
	})

	It("projects a perms action with mode 0o640 as canonical stored form", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "perms",
				Params: map[string]any{
					"path": "$ACTIVE/hello/bin/hi",
					"mode": "0o640",
				},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Action).To(Equal("perms"))
		Expect(own.Entries[0].Expected.Mode).To(Equal("0640"))
	})

	It("skips non-file-placing actions", func() {
		pkgRoot := writeInstallSource("x\n")
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "install",
					Params: map[string]any{"src": "$PKG/content/bin/hi", "dest": "$ACTIVE/hello/x", "policy": "symlink"}},
				// A future non-file-placing action (e.g. a service action) would also be skipped.
			},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: pkgRoot}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Action).To(Equal("install"))
	})

	It("defaults drift policy to notify_heal when unset", func() {
		pkgRoot := writeInstallSource("x\n")
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "install",
				Params: map[string]any{"src": "$PKG/content/bin/hi", "dest": "$ACTIVE/hello/x", "policy": "symlink"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: pkgRoot}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].DriftPolicy).To(Equal("notify_heal"))
	})
})

var _ = Describe("ProjectOwnership path action", func() {
	It("projects a bin/<name> symlink entry for the path action", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "path",
					Params: map[string]any{"name": "hello", "source": "$ACTIVE/hello/bin/hello"}},
			},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("bin/hello"))
		Expect(own.Entries[0].Action).To(Equal("path"))
		Expect(own.Entries[0].Expected.FileType).To(Equal("symlink"))
		Expect(own.Entries[0].Expected.Target).To(Equal("$ACTIVE/hello/bin/hello"))
	})
})

var _ = Describe("ProjectOwnership alternatives action", func() {
	It("projects a bin/<name> entry carrying priority and source", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "neovim", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "alternatives",
					Params: map[string]any{"name": "editor", "source": "$ACTIVE/neovim/bin/nvim", "priority": 30}},
			},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("bin/editor"))
		Expect(own.Entries[0].Action).To(Equal("alternatives"))
		Expect(own.Entries[0].Expected.FileType).To(Equal("symlink"))
		Expect(own.Entries[0].Expected.Target).To(Equal("$ACTIVE/neovim/bin/nvim"))
		Expect(own.Entries[0].Expected.Priority).To(Equal(30))
	})

	It("coerces a numeric-string priority (the Starlark-resolved form) to match apply", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "neovim", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "alternatives",
					Params: map[string]any{"name": "editor", "source": "$ACTIVE/neovim/bin/nvim", "priority": "30"}},
			},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Expected.Priority).To(Equal(30))
	})

	It("projects an alternatives follower at its link path with Master set", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "vim", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "alternatives",
				Params: map[string]any{
					"master": "editor",
					"link":   "man/man1/editor.1",
					"source": "$ACTIVE/vim/share/man/man1/vim.1",
				},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("man/man1/editor.1"))
		Expect(own.Entries[0].Expected.Master).To(Equal("editor"))
		Expect(own.Entries[0].Expected.Target).To(Equal("$ACTIVE/vim/share/man/man1/vim.1"))
		Expect(own.Entries[0].Expected.Priority).To(BeZero())
	})

	It("still projects an alternatives primary at bin/<name>", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "vim", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "alternatives",
				Params: map[string]any{"name": "editor", "source": "$ACTIVE/vim/bin/vim", "priority": 30},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].Path).To(Equal("bin/editor"))
		Expect(own.Entries[0].Expected.Priority).To(Equal(30))
		Expect(own.Entries[0].Expected.Master).To(BeEmpty())
	})
})

var _ = Describe("ProjectOwnership completion action", func() {
	It("projects a completions/<shell>/<hostfile> symlink entry (bash)", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "completion",
				Params: map[string]any{"shell": "bash", "name": "hi", "source": "$ACTIVE/hello/comp/hi.bash"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("completions/bash/hi"))
		Expect(own.Entries[0].Action).To(Equal("completion"))
		Expect(own.Entries[0].Expected.FileType).To(Equal("symlink"))
		Expect(own.Entries[0].Expected.Target).To(Equal("$ACTIVE/hello/comp/hi.bash"))
	})

	It("mirrors the per-shell host-file naming (zsh prefixes, fish suffixes)", func() {
		for shell, host := range map[string]string{"zsh": "_hi", "fish": "hi.fish"} {
			pkg := &schema.Package{
				Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
				Actions: []schema.PackageAction{{
					Phase: "post-place", Action: "completion",
					Params: map[string]any{"shell": shell, "name": "hi", "source": "$ACTIVE/hello/comp/hi." + shell},
				}},
			}
			own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
			Expect(err).NotTo(HaveOccurred(), "shell %q", shell)
			Expect(own.Entries[0].Path).To(Equal("completions/"+shell+"/"+host), "shell %q", shell)
		}
	})

	It("converges: a completion action projects the absolute target the runner stored", func() {
		const activeRoot = "/data/polypkg/generations/1/active"
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "completion",
				Params: map[string]any{"shell": "bash", "name": "hi", "source": "$ACTIVE/hello/comp/hi.bash"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].Path).To(Equal("completions/bash/hi"))
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/hello/comp/hi.bash"))
	})

	It("first apply (empty baseline) does not error on a completion action", func() {
		// Regression for the hard "relativize \"\"" error: completion has no
		// dest/path param, so the pre-fix projector produced an empty path and
		// filepath.Rel failed. The empty-baseline first-apply case must succeed.
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "completion",
				Params: map[string]any{"shell": "bash", "name": "hi", "source": "$ACTIVE/hello/comp/hi.bash"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
	})

	It("first apply (empty baseline) does not error on a desktop action", func() {
		// Regression for the hard "relativize \"\"" error: desktop has no
		// dest/path param, so the pre-fix projector produced an empty path and
		// filepath.Rel failed. The empty-baseline first-apply case must succeed.
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "desktop",
				Params: map[string]any{"source": "$ACTIVE/hello/share/applications/org.hello.App.desktop"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
	})

	It("first apply (empty baseline) does not error on a mime action", func() {
		// Regression for the hard "relativize \"\"" error: mime has no
		// dest/path param, so the pre-fix projector produced an empty path and
		// filepath.Rel failed. The empty-baseline first-apply case must succeed.
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "mime",
				Params: map[string]any{"source": "$ACTIVE/hello/share/mime/org.hello.App.xml"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
	})
})

var _ = Describe("ProjectOwnership desktop action", func() {
	It("projects an applications/<base> symlink entry", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "desktop",
				Params: map[string]any{"source": "$ACTIVE/hello/share/applications/org.hello.App.desktop"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("applications/org.hello.App.desktop"))
		Expect(own.Entries[0].Action).To(Equal("desktop"))
		Expect(own.Entries[0].Expected.FileType).To(Equal("symlink"))
		Expect(own.Entries[0].Expected.Target).To(Equal("$ACTIVE/hello/share/applications/org.hello.App.desktop"))
	})

	It("converges: a desktop action projects the absolute target the runner stored", func() {
		const activeRoot = "/data/polypkg/generations/1/active"
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "desktop",
				Params: map[string]any{"source": "$ACTIVE/hello/share/applications/org.hello.App.desktop"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].Path).To(Equal("applications/org.hello.App.desktop"))
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/hello/share/applications/org.hello.App.desktop"))
	})
})

var _ = Describe("ProjectOwnership mime action", func() {
	It("projects a mime/<base> symlink entry", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "mime",
				Params: map[string]any{"source": "$ACTIVE/hello/share/mime/org.hello.App.xml"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, "$ACTIVE", nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("mime/org.hello.App.xml"))
		Expect(own.Entries[0].Action).To(Equal("mime"))
		Expect(own.Entries[0].Expected.FileType).To(Equal("symlink"))
		Expect(own.Entries[0].Expected.Target).To(Equal("$ACTIVE/hello/share/mime/org.hello.App.xml"))
	})

	It("converges: a mime action projects the absolute target the runner stored", func() {
		const activeRoot = "/data/polypkg/generations/1/active"
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "mime",
				Params: map[string]any{"source": "$ACTIVE/hello/share/mime/org.hello.App.xml"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].Path).To(Equal("mime/org.hello.App.xml"))
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/hello/share/mime/org.hello.App.xml"))
	})
})

// These specs exercise the projected-target $ACTIVE expansion: when the caller
// supplies the diff baseline's active root (rather than the literal "$ACTIVE"
// placeholder), target-carrying actions project the fully-expanded absolute link
// target the runner stores at apply time, so a converged plan compares equal —
// while a genuinely different logical target still diffs.
var _ = Describe("ProjectOwnership target expansion against the baseline active root", func() {
	const activeRoot = "/data/polypkg/generations/1/active"

	It("converges: a path action projects the absolute target the runner stored", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "path",
				Params: map[string]any{"name": "hi", "source": "$ACTIVE/hello/bin/hi"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		// Path stays the relativized ownership key; only the link target expands.
		Expect(own.Entries[0].Path).To(Equal("bin/hi"))
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/hello/bin/hi"))
	})

	It("converges: a $ACTIVE-targeted symlink projects the absolute stored target", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "symlink",
				Params: map[string]any{"src": "$ACTIVE/hello/bin/hi", "dest": "$ACTIVE/hello/bin/hi-active"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("hello/bin/hi-active"))
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/hello/bin/hi"))
	})

	It("converges: an alternatives provider projects the absolute stored source", func() {
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "neovim", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "alternatives",
				Params: map[string]any{"name": "editor", "source": "$ACTIVE/neovim/bin/nvim", "priority": 30},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Path).To(Equal("bin/editor"))
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/neovim/bin/nvim"))
		Expect(own.Entries[0].Expected.Priority).To(Equal(30))
	})

	It("still diffs: a path action whose logical target moved projects a different absolute target", func() {
		// The runner stored .../hello/bin/hi; a profile that re-points the
		// command at .../hello/bin/hi2 must project a distinct target so the
		// diff still reports the real change.
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "path",
				Params: map[string]any{"name": "hi", "source": "$ACTIVE/hello/bin/hi2"},
			}},
		}
		own, err := ProjectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, activeRoot, nil, "user")
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries[0].Expected.Target).To(Equal(activeRoot + "/hello/bin/hi2"))
		Expect(own.Entries[0].Expected.Target).NotTo(Equal(activeRoot + "/hello/bin/hi"))
	})
})
