package profileedit_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/profileedit"
)

// baseJSONC is the canonical JSONC fixture. It contains:
//   - a block comment at the top
//   - inline (line) comments on several values
//   - trailing commas after the last member in each object
//   - two packages in the user scope (hello, world)
//
// These are the properties we assert are preserved through edits.
const baseJSONC = `/* polypkg profile — JSON with comments and trailing commas */
{
  "schema": "polypkg.spec/v1",
  "name": "my-machine", // hostname
  "scopes": {
    "user": {
      "substrate": "store" // no root needed
    },
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",   // package repository
      "trust_root": "/etc/polypkg/repo.pub",       // minisign public key
    },
  },
  "packages": {
    "user": {
      "hello": { "version": ">=1.0.0" },   // any 1.x or newer
      "world": { "version": "=2.0.0" },
    },
  },
}
`

// commentLinesJSONC returns the comment portion of each line in s that
// contains a // or /* marker. For // comments the text from // onward is
// returned; for block-comment delimiters the whole trimmed line is returned.
// This lets callers assert that a comment's text is preserved even when the
// non-comment portion of the same line changes (e.g. when a version is updated).
func commentLinesJSONC(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if i := strings.Index(t, "//"); i >= 0 {
			out = append(out, strings.TrimSpace(t[i:]))
		} else if strings.Contains(t, "/*") || strings.Contains(t, "*/") {
			out = append(out, t)
		}
	}
	return out
}

// writeJSONCProfile writes content to a fresh temp dir and returns the path.
func writeJSONCProfile(content string) string {
	dir := GinkgoT().TempDir()
	path := filepath.Join(dir, "profile.jsonc")
	Expect(os.WriteFile(path, []byte(content), 0o644)).To(Succeed())
	return path
}

// symlinkJSONCProfile creates real.jsonc with content and a symlink profile.jsonc -> real.jsonc.
func symlinkJSONCProfile(content string) (symlinkPath, realPath string) {
	dir := GinkgoT().TempDir()
	realPath = filepath.Join(dir, "real.jsonc")
	symlinkPath = filepath.Join(dir, "profile.jsonc")
	Expect(os.WriteFile(realPath, []byte(content), 0o644)).To(Succeed())
	Expect(os.Symlink(realPath, symlinkPath)).To(Succeed())
	return symlinkPath, realPath
}

var _ = Describe("Apply (JSONC)", func() {
	Describe("adding a package to an existing scope", func() {
		It("appends entry, preserves all comments and trailing commas elsewhere", func() {
			path := writeJSONCProfile(baseJSONC)
			before := readFile(path)
			commentsBefore := commentLinesJSONC(before)

			original, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "extra", Version: ">=3.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(original)).To(Equal(before))

			after := readFile(path)
			Expect(after).To(ContainSubstring(`"extra"`))

			// Existing packages keep their relative order; new one appended.
			helloIdx := strings.Index(after, `"hello"`)
			worldIdx := strings.Index(after, `"world"`)
			extraIdx := strings.Index(after, `"extra"`)
			Expect(helloIdx).To(BeNumerically(">", 0))
			Expect(helloIdx).To(BeNumerically("<", worldIdx))
			Expect(worldIdx).To(BeNumerically("<", extraIdx))

			// Every comment from the original survives.
			for _, c := range commentsBefore {
				Expect(commentLinesJSONC(after)).To(ContainElement(c))
			}

			p := reparse(path)
			Expect(p.Packages["user"]).To(HaveKey("extra"))
			Expect(p.Packages["user"]["extra"].Version).To(Equal(">=3.0.0"))
		})
	})

	Describe("updating the version of an existing package", func() {
		It("replaces only that version value and preserves comments", func() {
			path := writeJSONCProfile(baseJSONC)
			before := readFile(path)
			commentsBefore := commentLinesJSONC(before)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).NotTo(ContainSubstring(">=1.0.0"))
			Expect(after).To(ContainSubstring(`"=9.9.9"`))

			for _, c := range commentsBefore {
				Expect(commentLinesJSONC(after)).To(ContainElement(c))
			}

			Expect(reparse(path).Packages["user"]["hello"].Version).To(Equal("=9.9.9"))
		})
	})

	Describe("removing a package", func() {
		It("drops the entry and keeps remaining comments", func() {
			path := writeJSONCProfile(baseJSONC)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "world", Version: ""},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).NotTo(ContainSubstring(`"world"`))
			Expect(after).To(ContainSubstring(`"hello"`))
			// Block comment at top of file must still be present.
			Expect(after).To(ContainSubstring("polypkg profile"))

			// Comment count must not grow (world's inline comment is gone, rest retained).
			Expect(len(commentLinesJSONC(after))).To(BeNumerically("<=", len(commentLinesJSONC(before))))

			p := reparse(path)
			Expect(p.Packages["user"]).NotTo(HaveKey("world"))
			Expect(p.Packages["user"]).To(HaveKey("hello"))
		})

		It("returns NotInProfileError with sorted Known for an unknown name", func() {
			path := writeJSONCProfile(baseJSONC)
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

	Describe("missing parent containers", func() {
		// noPackagesJSONC is a valid profile without a packages section at all.
		const noPackagesJSONC = `{
  "schema": "polypkg.spec/v1",
  "name": "bare",
  "scopes": {
    "user": { "substrate": "store" },
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub",
    },
  },
}
`
		It("creates /packages and /packages/<scope> when absent", func() {
			path := writeJSONCProfile(noPackagesJSONC)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ">=1.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Packages["user"]["hello"].Version).To(Equal(">=1.0.0"))
		})

		// userOnlyJSONC has /packages/user but not /packages/system.
		const userOnlyJSONC = `{
  "schema": "polypkg.spec/v1",
  "name": "bare",
  "scopes": {
    "user": { "substrate": "store" },
    "system": { "substrate": "store" },
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub",
    },
  },
  "packages": {
    "user": {
      "hello": { "version": ">=1.0.0" },
    },
  },
}
`
		It("creates a missing scope under an existing packages map", func() {
			path := writeJSONCProfile(userOnlyJSONC)

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
		const onePackageJSONC = `{
  "schema": "polypkg.spec/v1",
  "name": "bare",
  "scopes": {
    "user": { "substrate": "store" },
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub",
    },
  },
  "packages": {
    "user": {
      "hello": { "version": ">=1.0.0" },
    },
  },
}
`
		It("leaves an empty scope object and file stays schema-valid", func() {
			path := writeJSONCProfile(onePackageJSONC)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ""},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Packages["user"]).To(BeEmpty())
		})
	})

	Describe("round-trip restore", func() {
		It("returns exact original bytes and Restore yields byte-identical file", func() {
			path := writeJSONCProfile(baseJSONC)
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
			path := writeJSONCProfile(baseJSONC)

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

	Describe("validation gate", func() {
		It("rejects an invalid package name and leaves the file unchanged", func() {
			path := writeJSONCProfile(baseJSONC)
			before := readFile(path)

			// A package name with a space violates schema propertyNames ^[a-zA-Z0-9_-]+$.
			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "bad name", Version: ">=1.0.0"},
			})
			Expect(err).To(HaveOccurred())
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("symlinked .jsonc profile (dotfile setup)", func() {
		It("leaves profile.jsonc as a symlink and edits real.jsonc through it", func() {
			symlinkPath, realPath := symlinkJSONCProfile(baseJSONC)

			original, err := profileedit.Apply(symlinkPath, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(original)).To(Equal(baseJSONC))

			// (a) profile.jsonc must still be a symlink.
			linfo, lerr := os.Lstat(symlinkPath)
			Expect(lerr).NotTo(HaveOccurred())
			Expect(linfo.Mode() & os.ModeSymlink).To(Equal(os.ModeSymlink))

			// (b) real.jsonc must contain the edit.
			realContent := readFile(realPath)
			Expect(realContent).To(ContainSubstring(`"=9.9.9"`))
			Expect(realContent).NotTo(ContainSubstring(">=1.0.0"))

			// (c) Restore via symlink path reverts real.jsonc; link stays intact.
			Expect(profileedit.Restore(symlinkPath, original)).To(Succeed())
			Expect(readFile(realPath)).To(Equal(baseJSONC))
			linfo2, lerr2 := os.Lstat(symlinkPath)
			Expect(lerr2).NotTo(HaveOccurred())
			Expect(linfo2.Mode() & os.ModeSymlink).To(Equal(os.ModeSymlink))
		})
	})

	Describe("malformed packages node (I1)", func() {
		It("returns a friendly error when packages is not an object", func() {
			// "packages": [] — array, not object; hujson.Patch would panic with
			// "invalid array index: user" without the pre-check.
			const malformedPkgs = `{
  "schema": "polypkg.spec/v1",
  "name": "bad",
  "scopes": { "user": { "substrate": "store" } },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub",
    },
  },
  "packages": [],
}
`
			path := writeJSONCProfile(malformedPkgs)
			before := readFile(path)

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: ">=1.0.0"},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("profile structure is malformed"))
			Expect(err.Error()).To(ContainSubstring("packages is not a map"))
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})

		It("returns a friendly error when a scope node is not an object", func() {
			const malformedScope = `{
  "schema": "polypkg.spec/v1",
  "name": "bad",
  "scopes": { "user": { "substrate": "store" } },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub",
    },
  },
  "packages": { "user": [] },
}
`
			path := writeJSONCProfile(malformedScope)
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

	Describe("mode preservation", func() {
		It("keeps the original file mode (0600) after an edit", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "profile.jsonc")
			Expect(os.WriteFile(path, []byte(baseJSONC), 0o600)).To(Succeed())

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "hello", Version: "=9.9.9"},
			})
			Expect(err).NotTo(HaveOccurred())

			info, err := os.Stat(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		})
	})

	Describe("constraint quoting for JSONC", func() {
		It("keeps >=, =, and * constraints as strings across a re-parse", func() {
			path := writeJSONCProfile(baseJSONC)

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

	Describe("no injected comments on add (JSONC)", func() {
		It("comment count does not grow after adding a package", func() {
			path := writeJSONCProfile(baseJSONC)
			before := readFile(path)
			commentCountBefore := len(commentLinesJSONC(before))

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "extra", Version: ">=3.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(len(commentLinesJSONC(after))).To(Equal(commentCountBefore))
		})
	})

	Describe("plain .json file (no comments)", func() {
		// Exercises the .json extension — identical code path, no JWCC extras.
		const plainJSON = `{
  "schema": "polypkg.spec/v1",
  "name": "json-machine",
  "scopes": {
    "user": { "substrate": "store" }
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub"
    }
  },
  "packages": {
    "user": {
      "hello": { "version": ">=1.0.0" }
    }
  }
}
`
		It("adds and removes packages in a .json file", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "profile.json")
			Expect(os.WriteFile(path, []byte(plainJSON), 0o644)).To(Succeed())

			_, err := profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "world", Version: "=2.0.0"},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Packages["user"]["hello"].Version).To(Equal(">=1.0.0"))
			Expect(p.Packages["user"]["world"].Version).To(Equal("=2.0.0"))

			_, err = profileedit.Apply(path, []profileedit.Edit{
				{Scope: "user", Name: "world", Version: ""},
			})
			Expect(err).NotTo(HaveOccurred())
			p = reparse(path)
			Expect(p.Packages["user"]).NotTo(HaveKey("world"))
		})
	})
})
