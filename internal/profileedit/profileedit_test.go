package profileedit_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/profileedit"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// symlinkProfile creates real.yaml with content, then a symlink profile.yaml ->
// real.yaml. Returns (symlinkPath, realPath).
func symlinkProfile(content string) (symlinkPath, realPath string) {
	dir := GinkgoT().TempDir()
	realPath = filepath.Join(dir, "real.yaml")
	symlinkPath = filepath.Join(dir, "profile.yaml")
	Expect(os.WriteFile(realPath, []byte(content), 0o644)).To(Succeed())
	Expect(os.Symlink(realPath, symlinkPath)).To(Succeed())
	return symlinkPath, realPath
}

// baseProfile is a fully commented profile exercising inline comments,
// above-key comments, and a top-of-file comment. It is the canonical
// fixture for "comments survive" assertions.
const baseProfile = `# polypkg profile: the single source of truth for what's installed.
schema: polypkg.spec/v1
name: my-machine
scopes:
  user:                # installs under your home, no root needed
    substrate: store   # the content store backend (the default choice)
sources:
  order: [native]      # which sources to consult, in order
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg     # your package repository
    trust_root: /etc/polypkg/repo.pub         # path to the repo's minisign public key
packages:
  user:
    hello:
      version: ">=1.0.0"   # any 1.x or newer; use "=1.0.0" to pin exactly
    world:
      version: "=2.0.0"
`

// commentLines returns every line of s that contains a YAML comment marker,
// trimmed of surrounding whitespace and with runs of internal spaces before
// the comment collapsed, so they can be compared across the canonical
// reformat (which collapses multiple spaces before an inline comment to one).
func commentLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			out = append(out, strings.TrimSpace(line[i:]))
		}
	}
	return out
}

// writeProfile creates a profile file in a fresh temp dir and returns its path.
func writeProfile(content string) string {
	dir := GinkgoT().TempDir()
	path := filepath.Join(dir, "profile.yaml")
	Expect(os.WriteFile(path, []byte(content), 0o644)).To(Succeed())
	return path
}

// readFile reads a file and fails the spec on error.
func readFile(path string) string {
	b, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

// reparse parses the file at path with the schema parser and returns the Profile.
func reparse(path string) *schema.Profile {
	f, err := os.Open(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	p, err := schema.ParseProfile(f, path)
	Expect(err).NotTo(HaveOccurred())
	return p
}

var _ = Describe("Apply", func() {
	Describe("adding a package to an existing scope", func() {
		It("keeps all comments, leaves untouched entries in order, and reparses", func() {
			path := writeProfile(baseProfile)
			before := readFile(path)

			original, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "extra", Version: ">=3.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(original)).To(Equal(before))

			after := readFile(path)
			// Every comment from the original survives.
			for _, c := range commentLines(before) {
				Expect(commentLines(after)).To(ContainElement(c))
			}
			// No injected comments: comment count must not grow.
			Expect(len(commentLines(after))).To(Equal(len(commentLines(before))))
			// Existing packages keep their relative order, new one appended.
			helloIdx := strings.Index(after, "hello:")
			worldIdx := strings.Index(after, "world:")
			extraIdx := strings.Index(after, "extra:")
			Expect(helloIdx).To(BeNumerically(">", 0))
			Expect(helloIdx).To(BeNumerically("<", worldIdx))
			Expect(worldIdx).To(BeNumerically("<", extraIdx))

			p := reparse(path)
			Expect(p.Packages["user"]).To(HaveKey("extra"))
			Expect(p.Packages["user"]["extra"].Version).To(Equal(">=3.0.0"))
		})
	})

	Describe("updating the version of an existing package", func() {
		It("changes only that scalar and keeps comments", func() {
			path := writeProfile(baseProfile)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).NotTo(ContainSubstring(">=1.0.0"))
			Expect(after).To(ContainSubstring(`"=9.9.9"`))
			for _, c := range commentLines(before) {
				Expect(commentLines(after)).To(ContainElement(c))
			}
			Expect(len(commentLines(after))).To(Equal(len(commentLines(before))))
			Expect(reparse(path).Packages["user"]["hello"].Version).To(Equal("=9.9.9"))
		})
	})

	Describe("removing a package", func() {
		It("drops the entry and keeps remaining comments", func() {
			path := writeProfile(baseProfile)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "world", Version: ""},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).NotTo(ContainSubstring("world:"))
			Expect(after).To(ContainSubstring("hello:"))
			Expect(after).To(ContainSubstring("single source of truth"))
			// Comments not injected: count must not grow (world's comment is gone, rest kept).
			Expect(len(commentLines(after))).To(BeNumerically("<=", len(commentLines(before))))
			p := reparse(path)
			Expect(p.Packages["user"]).NotTo(HaveKey("world"))
			Expect(p.Packages["user"]).To(HaveKey("hello"))
		})

		It("returns NotInProfileError with sorted Known for an unknown name", func() {
			path := writeProfile(baseProfile)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "ghost", Version: ""},
			})
			var nipe *profileedit.NotInProfileError
			Expect(errors.As(err, &nipe)).To(BeTrue())
			Expect(nipe.Name).To(Equal("ghost"))
			Expect(nipe.Scope).To(Equal("user"))
			Expect(nipe.Known).To(Equal([]string{"hello", "world"}))
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("adding when packages/scope sections are absent", func() {
		It("creates the structure and stays valid", func() {
			const noPackages = `schema: polypkg.spec/v1
name: bare
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg
    trust_root: /etc/polypkg/repo.pub
`
			path := writeProfile(noPackages)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ">=1.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Packages["user"]["hello"].Version).To(Equal(">=1.0.0"))
		})

		It("creates a missing scope under an existing packages map", func() {
			const userOnly = `schema: polypkg.spec/v1
name: bare
scopes:
  user:
    substrate: store
  system:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg
    trust_root: /etc/polypkg/repo.pub
packages:
  user:
    hello:
      version: ">=1.0.0"
`
			path := writeProfile(userOnly)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "system", Name: "tool", Version: "=1.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Packages["system"]["tool"].Version).To(Equal("=1.0.0"))
			Expect(p.Packages["user"]["hello"].Version).To(Equal(">=1.0.0"))
		})
	})

	Describe("removing the last package in a scope", func() {
		It("leaves an empty scope map and the file stays schema-valid", func() {
			const oneEach = `schema: polypkg.spec/v1
name: bare
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg
    trust_root: /etc/polypkg/repo.pub
packages:
  user:
    hello:
      version: ">=1.0.0"
`
			path := writeProfile(oneEach)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ""},
			})
			Expect(err).NotTo(HaveOccurred())

			// Reparses without error (schema-valid).
			p := reparse(path)
			Expect(p.Packages["user"]).To(BeEmpty())
		})
	})

	Describe("round-trip restore", func() {
		It("returns exact original bytes and Restore yields a byte-identical file", func() {
			path := writeProfile(baseProfile)
			before := readFile(path)

			original, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(original)).To(Equal(before))

			Expect(profileedit.Restore(path, original)).To(Succeed())
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("idempotency", func() {
		It("produces identical bytes when the same edit is applied twice", func() {
			path := writeProfile(baseProfile)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())
			first := readFile(path)

			_, err = profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())
			second := readFile(path)

			Expect(second).To(Equal(first))
		})
	})

	Describe("constraint quoting", func() {
		It("keeps >=, =, and * constraints as strings across re-parse", func() {
			path := writeProfile(baseProfile)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "a", Version: ">=1.0.0"},
				{Scope: "user", Name: "b", Version: "=1.2.3"},
				{Scope: "user", Name: "c", Version: "*"},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Packages["user"]["a"].Version).To(Equal(">=1.0.0"))
			Expect(p.Packages["user"]["b"].Version).To(Equal("=1.2.3"))
			Expect(p.Packages["user"]["c"].Version).To(Equal("*"))
		})
	})

	Describe("validation gate", func() {
		It("rejects an edit producing an invalid profile and leaves the file unchanged", func() {
			path := writeProfile(baseProfile)
			before := readFile(path)

			// A package name with a space violates the schema's
			// propertyNames pattern ^[a-zA-Z0-9_-]+$.
			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "bad name", Version: ">=1.0.0"},
			})
			Expect(err).To(HaveOccurred())
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("mode preservation", func() {
		It("keeps the original file mode after an edit", func() {
			path := writeProfile(baseProfile)
			Expect(os.Chmod(path, 0o600)).To(Succeed())

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())

			info, err := os.Stat(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		})
	})

	Describe("symlinked profile (dotfile setup)", func() {
		It("leaves profile.yaml as a symlink and edits real.yaml", func() {
			symlinkPath, realPath := symlinkProfile(baseProfile)

			original, err := profileedit.Apply(symlinkPath, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(original)).To(Equal(baseProfile))

			// (a) profile.yaml must still be a symlink.
			linfo, lerr := os.Lstat(symlinkPath)
			Expect(lerr).NotTo(HaveOccurred())
			Expect(linfo.Mode() & os.ModeSymlink).To(Equal(os.ModeSymlink))

			// (b) real.yaml must contain the edit.
			realContent := readFile(realPath)
			Expect(realContent).To(ContainSubstring(`"=9.9.9"`))
			Expect(realContent).NotTo(ContainSubstring(">=1.0.0"))

			// (c) Restore via symlink path reverts real.yaml; link stays intact.
			Expect(profileedit.Restore(symlinkPath, original)).To(Succeed())
			Expect(readFile(realPath)).To(Equal(baseProfile))
			linfo2, lerr2 := os.Lstat(symlinkPath)
			Expect(lerr2).NotTo(HaveOccurred())
			Expect(linfo2.Mode() & os.ModeSymlink).To(Equal(os.ModeSymlink))
		})
	})

	Describe("malformed packages node", func() {
		It("returns a typed error when packages is not a map", func() {
			const malformed = `schema: polypkg.spec/v1
name: bad
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg
    trust_root: /etc/polypkg/repo.pub
packages: notamap
`
			path := writeProfile(malformed)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ">=1.0.0"},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("profile structure is malformed"))
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})

		It("returns a typed error when a scope node is not a map", func() {
			const malformed = `schema: polypkg.spec/v1
name: bad
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg
    trust_root: /etc/polypkg/repo.pub
packages:
  user: notamap
`
			path := writeProfile(malformed)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ">=1.0.0"},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("profile structure is malformed"))
			Expect(err.Error()).To(ContainSubstring("packages.user"))
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})
	})

})

var _ = Describe("Restore", func() {
	It("writes the bytes verbatim", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "profile.yaml")
		Expect(os.WriteFile(path, []byte("placeholder"), 0o644)).To(Succeed())

		want := []byte("schema: polypkg.spec/v1\n")
		Expect(profileedit.Restore(path, want)).To(Succeed())
		Expect(bytes.Equal([]byte(readFile(path)), want)).To(BeTrue())
	})
})
