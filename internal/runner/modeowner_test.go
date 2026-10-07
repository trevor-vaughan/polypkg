package runner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// readmeTarGz is a .tar.gz holding one 0644 file, doc/README.
func readmeTarGz() []byte {
	GinkgoHelper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	body := "readme\n"
	Expect(tw.WriteHeader(&tar.Header{Name: "doc/README", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})).To(Succeed())
	_, err := tw.Write([]byte(body))
	Expect(err).NotTo(HaveOccurred())
	Expect(tw.Close()).To(Succeed())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err = zw.Write(raw.Bytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(zw.Close()).To(Succeed())
	return gz.Bytes()
}

// runTwice applies pkg (rooted at pkgRoot) twice under a fresh store and
// returns the substrate. The second apply inspects the first generation for
// drift, so it fails if the recorded ownership disagrees with what the first
// apply left on disk.
func runTwice(dir string, pkg *schema.Package, pkgRoot string) substrate.Substrate {
	GinkgoHelper()
	sub, err := substrate.NewOwnStore(filepath.Join(dir, "store"))
	Expect(err).NotTo(HaveOccurred())
	r := New(Options{Substrate: sub, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"), DirMode: 0o700})
	m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
	entries := []RunEntry{{Package: pkg, PkgRoot: pkgRoot}}
	_, err = r.Run(context.Background(), m, entries)
	Expect(err).NotTo(HaveOccurred())
	gen, err := r.Run(context.Background(), m, entries)
	Expect(err).NotTo(HaveOccurred(), "a re-apply must find no drift on a path perms re-moded")
	Expect(gen).To(Equal(2))
	return sub
}

// entriesAt returns the current generation's ownership entries for path.
func entriesAt(sub substrate.Substrate, path string) []schema.OwnershipEntry {
	GinkgoHelper()
	own, _, _, err := sub.CurrentOwnership()
	Expect(err).NotTo(HaveOccurred())
	var out []schema.OwnershipEntry
	for _, e := range own.Entries {
		if e.Path == path {
			out = append(out, e)
		}
	}
	return out
}

var _ = Describe("Run with perms re-moding an earlier action's path", func() {
	It("enforces only the perms mode on a dir the dir action created", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "dir", Drift: "refuse",
					Params: map[string]any{"path": "$ACTIVE/hello/var", "mode": "0755"}},
				{Phase: "post-place", Action: "perms", Drift: "refuse",
					Params: map[string]any{"path": "$ACTIVE/hello/var", "mode": "0700"}},
			},
		}
		sub := runTwice(dir, pkg, pkgRoot)

		got := entriesAt(sub, "hello/var")
		Expect(got).To(HaveLen(2))
		Expect(got[0].Action).To(Equal("dir"))
		Expect(got[0].Expected).To(Equal(schema.Expected{FileType: "dir"}),
			"the dir entry keeps its type but leaves the mode to the later perms")
		Expect(got[1].Action).To(Equal("perms"))
		Expect(got[1].Expected.Mode).To(Equal("0700"))
	})

	It("enforces only the perms mode on a file the extract action placed", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "content"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(pkgRoot, "content", "docs.tar.gz"), readmeTarGz(), 0o644)).To(Succeed())
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "extract", Drift: "refuse",
					Params: map[string]any{"src": "$PKG/content/docs.tar.gz", "dest": "$ACTIVE/hello/share"}},
				{Phase: "post-place", Action: "perms", Drift: "refuse",
					Params: map[string]any{"path": "$ACTIVE/hello/share/doc/README", "mode": "0600"}},
			},
		}
		sub := runTwice(dir, pkg, pkgRoot)

		got := entriesAt(sub, "hello/share/doc/README")
		Expect(got).To(HaveLen(2))
		Expect(got[0].Action).To(Equal("extract"))
		Expect(got[0].Expected.Mode).To(BeEmpty())
		Expect(got[0].Expected.FileType).To(Equal("regular"))
		Expect(got[0].Expected.ContentHash).NotTo(BeEmpty(), "content is still enforced")
		Expect(got[1].Expected.Mode).To(Equal("0600"))
	})

	It("still refuses a later chmod away from the perms mode", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "dir", Drift: "refuse",
					Params: map[string]any{"path": "$ACTIVE/hello/var", "mode": "0755"}},
				{Phase: "post-place", Action: "perms", Drift: "refuse",
					Params: map[string]any{"path": "$ACTIVE/hello/var", "mode": "0700"}},
			},
		}
		sub := runTwice(dir, pkg, pkgRoot)
		_, _, active, err := sub.CurrentOwnership()
		Expect(err).NotTo(HaveOccurred())
		Expect(os.Chmod(filepath.Join(active, "hello", "var"), 0o755)).To(Succeed())

		r := New(Options{Substrate: sub, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"), DirMode: 0o700})
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = r.Run(context.Background(), m, []RunEntry{{Package: pkg, PkgRoot: pkgRoot}})
		Expect(err).To(MatchError(ContainSubstring("apply refused")))
	})
})

var _ = Describe("Run against a generation recorded before modes were superseded", func() {
	It("checks drift only against the last mode set, so the first apply is not refused", func() {
		root := GinkgoT().TempDir()
		own := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{
				{Path: "hello/var", Package: "hello", Version: "1.0.0", Action: "dir",
					Expected: schema.Expected{FileType: "dir", Mode: "0755"}, DriftPolicy: "refuse"},
				{Path: "hello/var", Package: "hello", Version: "1.0.0", Action: "perms",
					Expected: schema.Expected{Mode: "0700"}, DriftPolicy: "refuse"},
			},
		}
		sub := stageGeneration(root, own)
		Expect(os.Chmod(filepath.Join(root, "generations/1/active/hello/var"), 0o700)).To(Succeed())

		r := New(Options{Substrate: sub, Scope: "user", LockPath: filepath.Join(root, "apply.lock")})
		gen, err := r.Run(context.Background(),
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(gen).To(Equal(2))
	})
})
