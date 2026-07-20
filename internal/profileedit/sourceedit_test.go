package profileedit_test

import (
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/profileedit"
)

// baseProfileWithComment is the canonical YAML fixture that includes comments on
// lines that ApplySourceEdits does not touch, so we can assert those comments
// survive the edit.
const baseProfileWithComment = `# polypkg profile: the single source of truth for what's installed.
schema: polypkg.spec/v1
name: my-machine
scopes:
  user: # installs under your home, no root needed
    substrate: store
sources:
  order: [native]      # which sources to consult, in order
  native:
    type: polypkg-native
    url: https://repo.example.com/polypkg     # your package repository
    trust_root: /etc/polypkg/repo.pub         # path to the repo's minisign public key
packages:
  user:
    hello:
      version: ">=1.0.0"
`

// minimalProfile is a valid profile with a single source; used for tests that
// need a clean slate without the extra package noise.
const minimalProfile = `schema: polypkg.spec/v1
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

// sourceEditComment returns the comment text from every line in s that starts
// with the polypkg profile header (the first comment line). This is the
// survivor comment we assert in preservation tests.
func topComment(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

var _ = Describe("ApplySourceEdits (YAML)", func() {

	Describe("add source to a profile that already has one source", func() {
		It("appends extra to sources and to order, preserves existing source and all comments", func() {
			path := writeProfile(baseProfileWithComment)
			before := readFile(path)

			original, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "extra",
					Type:      "polypkg-native",
					URL:       "https://extra.example.com/polypkg",
					TrustRoot: "/etc/polypkg/extra.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(string(original)).To(Equal(before))

			after := readFile(path)

			// "native" still present.
			Expect(after).To(ContainSubstring("native:"))
			// "extra" appended.
			Expect(after).To(ContainSubstring("extra:"))

			// Top-of-file comment survives.
			Expect(topComment(after)).To(Equal(topComment(before)))

			// order has both entries; native first, extra second.
			nativeOrderIdx := strings.Index(after, "native")
			Expect(nativeOrderIdx).To(BeNumerically(">", 0))

			// Re-parse validates schema and shows the new source.
			p := reparse(path)
			Expect(p.Sources.Sources).To(HaveKey("extra"))
			Expect(p.Sources.Sources["extra"].URL).To(Equal("https://extra.example.com/polypkg"))
			Expect(p.Sources.Sources["extra"].TrustRoot).To(Equal("/etc/polypkg/extra.pub"))
			Expect(p.Sources.Order).To(ContainElement("native"))
			Expect(p.Sources.Order).To(ContainElement("extra"))
			// native appears before extra in order.
			nIdx := indexOf(p.Sources.Order, "native")
			eIdx := indexOf(p.Sources.Order, "extra")
			Expect(nIdx).To(BeNumerically("<", eIdx))
		})
	})

	Describe("add with OrderFirst", func() {
		It("prepends the new source to order", func() {
			path := writeProfile(minimalProfile)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:       "priority",
					Type:       "polypkg-native",
					URL:        "https://priority.example.com/polypkg",
					TrustRoot:  "/etc/polypkg/priority.pub",
					OrderFirst: true,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Sources.Order[0]).To(Equal("priority"))
			Expect(p.Sources.Order).To(ContainElement("native"))
		})
	})

	Describe("update existing source", func() {
		It("changes url and trust_root in place; order unchanged and has one entry", func() {
			path := writeProfile(minimalProfile)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "native",
					Type:      "polypkg-native",
					URL:       "https://updated.example.com/polypkg",
					TrustRoot: "/etc/polypkg/updated.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).To(ContainSubstring("updated.example.com"))
			Expect(after).NotTo(ContainSubstring("repo.example.com"))

			p := reparse(path)
			Expect(p.Sources.Sources["native"].URL).To(Equal("https://updated.example.com/polypkg"))
			Expect(p.Sources.Sources["native"].TrustRoot).To(Equal("/etc/polypkg/updated.pub"))
			// Order has exactly one "native" entry.
			count := 0
			for _, o := range p.Sources.Order {
				if o == "native" {
					count++
				}
			}
			Expect(count).To(Equal(1))
		})
	})

	Describe("remove source", func() {
		It("drops the source entry and its order entry", func() {
			path := writeProfile(baseProfileWithComment)
			before := readFile(path)

			// First add a second source so we can remove it without
			// leaving the profile with an empty order (schema requires minItems:1).
			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "extra",
					Type:      "polypkg-native",
					URL:       "https://extra.example.com/polypkg",
					TrustRoot: "/etc/polypkg/extra.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{Name: "extra", Remove: true},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).NotTo(ContainSubstring("extra:"))
			Expect(after).To(ContainSubstring("native:"))

			// Top-of-file comment from original still intact.
			Expect(topComment(after)).To(Equal(topComment(before)))

			p := reparse(path)
			Expect(p.Sources.Sources).NotTo(HaveKey("extra"))
			Expect(p.Sources.Sources).To(HaveKey("native"))
			Expect(p.Sources.Order).NotTo(ContainElement("extra"))
			Expect(p.Sources.Order).To(ContainElement("native"))
		})

		It("returns SourceNotInProfileError for an absent source name", func() {
			path := writeProfile(minimalProfile)
			before := readFile(path)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{Name: "ghost", Remove: true},
			})
			var snipe *profileedit.SourceNotInProfileError
			Expect(errors.As(err, &snipe)).To(BeTrue())
			Expect(snipe.Name).To(Equal("ghost"))
			Expect(snipe.Known).To(Equal([]string{"native"}))
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("reserved source name", func() {
		It("rejects an add of a source named \"order\" without touching the file", func() {
			path := writeProfile(minimalProfile)
			before := readFile(path)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      profileedit.ReservedSourceName,
					Type:      "polypkg-native",
					URL:       "https://order.example.com/polypkg",
					TrustRoot: "/etc/polypkg/order.pub",
				},
			})
			Expect(errors.Is(err, profileedit.ErrReservedSourceName)).To(BeTrue(),
				"expected ErrReservedSourceName, got %v", err)
			// File must be byte-for-byte unchanged (no corruption of order array).
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("YAML comment preservation", func() {
		It("all comments on untouched lines survive a source add", func() {
			path := writeProfile(baseProfileWithComment)
			before := readFile(path)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "secondary",
					Type:      "polypkg-native",
					URL:       "https://secondary.example.com/polypkg",
					TrustRoot: "/etc/polypkg/secondary.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			commentsBefore := commentLines(before)
			commentsAfter := commentLines(after)
			for _, c := range commentsBefore {
				Expect(commentsAfter).To(ContainElement(c))
			}
			// No injected comments.
			Expect(len(commentsAfter)).To(Equal(len(commentsBefore)))
		})
	})

	Describe("round-trip schema validity", func() {
		It("profile is schema-valid after add, update, and remove", func() {
			path := writeProfile(minimalProfile)

			// Add.
			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "secondary",
					Type:      "polypkg-native",
					URL:       "https://secondary.example.com/polypkg",
					TrustRoot: "/etc/polypkg/secondary.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_ = reparse(path)

			// Update.
			_, err = profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "secondary",
					Type:      "polypkg-native",
					URL:       "https://updated.example.com/polypkg",
					TrustRoot: "/etc/polypkg/updated.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			p := reparse(path)
			Expect(p.Sources.Sources["secondary"].URL).To(Equal("https://updated.example.com/polypkg"))

			// Remove.
			_, err = profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{Name: "secondary", Remove: true},
			})
			Expect(err).NotTo(HaveOccurred())
			p = reparse(path)
			Expect(p.Sources.Sources).NotTo(HaveKey("secondary"))
		})
	})

	Describe("idempotency", func() {
		It("applying the same add twice produces identical output", func() {
			path := writeProfile(minimalProfile)

			edit := []profileedit.SourceEdit{{
				Name:      "extra",
				Type:      "polypkg-native",
				URL:       "https://extra.example.com/polypkg",
				TrustRoot: "/etc/polypkg/extra.pub",
			}}
			_, err := profileedit.ApplySourceEdits(path, edit)
			Expect(err).NotTo(HaveOccurred())
			first := readFile(path)

			_, err = profileedit.ApplySourceEdits(path, edit)
			Expect(err).NotTo(HaveOccurred())
			second := readFile(path)

			Expect(second).To(Equal(first))
		})
	})
})

var _ = Describe("ApplySourceEdits (JSONC)", func() {

	// baseJSONCWithSource is a JSONC profile with a single source.
	const baseJSONCWithSource = `/* polypkg profile — JSONC */
{
  "schema": "polypkg.spec/v1",
  "name": "my-machine", // hostname
  "scopes": {
    "user": { "substrate": "store" },
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",   // package repository
      "trust_root": "/etc/polypkg/repo.pub",       // minisign public key
    },
  },
}
`

	Describe("add source to a JSONC profile", func() {
		It("inserts the new source and appends to order; comments preserved", func() {
			path := writeJSONCProfile(baseJSONCWithSource)
			before := readFile(path)
			commentsBefore := commentLinesJSONC(before)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "secondary",
					Type:      "polypkg-native",
					URL:       "https://secondary.example.com/polypkg",
					TrustRoot: "/etc/polypkg/secondary.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).To(ContainSubstring(`"secondary"`))

			for _, c := range commentsBefore {
				Expect(commentLinesJSONC(after)).To(ContainElement(c))
			}

			p := reparse(path)
			Expect(p.Sources.Sources).To(HaveKey("secondary"))
			Expect(p.Sources.Sources["secondary"].URL).To(Equal("https://secondary.example.com/polypkg"))
			Expect(p.Sources.Order).To(ContainElements("native", "secondary"))
		})
	})

	Describe("add with OrderFirst in JSONC", func() {
		It("prepends to order", func() {
			path := writeJSONCProfile(baseJSONCWithSource)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:       "priority",
					Type:       "polypkg-native",
					URL:        "https://priority.example.com/polypkg",
					TrustRoot:  "/etc/polypkg/priority.pub",
					OrderFirst: true,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Sources.Order[0]).To(Equal("priority"))
		})
	})

	Describe("update existing source in JSONC", func() {
		It("replaces url and trust_root; order has one entry for the name", func() {
			path := writeJSONCProfile(baseJSONCWithSource)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "native",
					Type:      "polypkg-native",
					URL:       "https://updated.example.com/polypkg",
					TrustRoot: "/etc/polypkg/updated.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Sources.Sources["native"].URL).To(Equal("https://updated.example.com/polypkg"))
			count := 0
			for _, o := range p.Sources.Order {
				if o == "native" {
					count++
				}
			}
			Expect(count).To(Equal(1))
		})
	})

	Describe("JSONC update preserves unmanaged source keys (trust_doc)", func() {
		// baseJSONCWithTrustDoc is like baseJSONCWithSource but the native source
		// carries an extra trust_doc key that ApplySourceEdits does not manage.
		// An update must leave trust_doc intact.
		const baseJSONCWithTrustDoc = `/* polypkg profile — JSONC with trust_doc */
{
  "schema": "polypkg.spec/v1",
  "name": "my-machine",
  "scopes": {
    "user": { "substrate": "store" },
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://repo.example.com/polypkg",
      "trust_root": "/etc/polypkg/repo.pub",
      "trust_doc": "/etc/polypkg/native.trust",
    },
  },
}
`
		It("updates url and trust_root but leaves trust_doc unchanged", func() {
			path := writeJSONCProfile(baseJSONCWithTrustDoc)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "native",
					Type:      "polypkg-native",
					URL:       "https://updated.example.com/polypkg",
					TrustRoot: "/etc/polypkg/updated.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			p := reparse(path)
			Expect(p.Sources.Sources["native"].URL).To(Equal("https://updated.example.com/polypkg"))
			Expect(p.Sources.Sources["native"].TrustRoot).To(Equal("/etc/polypkg/updated.pub"))
			// trust_doc must survive the update untouched.
			Expect(p.Sources.Sources["native"].TrustDoc).To(Equal("/etc/polypkg/native.trust"))
		})
	})

	Describe("reserved source name in JSONC", func() {
		It("rejects an add of a source named \"order\" without touching the file", func() {
			path := writeJSONCProfile(baseJSONCWithSource)
			before := readFile(path)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      profileedit.ReservedSourceName,
					Type:      "polypkg-native",
					URL:       "https://order.example.com/polypkg",
					TrustRoot: "/etc/polypkg/order.pub",
				},
			})
			Expect(errors.Is(err, profileedit.ErrReservedSourceName)).To(BeTrue(),
				"expected ErrReservedSourceName, got %v", err)
			Expect(readFile(path)).To(Equal(before))
		})
	})

	Describe("remove source in JSONC", func() {
		It("drops the source and its order entry", func() {
			path := writeJSONCProfile(baseJSONCWithSource)

			// Add a second source first.
			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{
					Name:      "extra",
					Type:      "polypkg-native",
					URL:       "https://extra.example.com/polypkg",
					TrustRoot: "/etc/polypkg/extra.pub",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{Name: "extra", Remove: true},
			})
			Expect(err).NotTo(HaveOccurred())

			after := readFile(path)
			Expect(after).NotTo(ContainSubstring(`"extra"`))

			p := reparse(path)
			Expect(p.Sources.Sources).NotTo(HaveKey("extra"))
			Expect(p.Sources.Order).NotTo(ContainElement("extra"))
			Expect(p.Sources.Order).To(ContainElement("native"))
		})

		It("returns SourceNotInProfileError for an absent source name", func() {
			path := writeJSONCProfile(baseJSONCWithSource)
			before := readFile(path)

			_, err := profileedit.ApplySourceEdits(path, []profileedit.SourceEdit{
				{Name: "ghost", Remove: true},
			})
			var snipe *profileedit.SourceNotInProfileError
			Expect(errors.As(err, &snipe)).To(BeTrue())
			Expect(snipe.Name).To(Equal("ghost"))
			Expect(snipe.Known).To(Equal([]string{"native"}))
			// File untouched.
			Expect(readFile(path)).To(Equal(before))
		})
	})
})

// indexOf returns the index of v in s, or -1 if not found.
func indexOf(s []string, v string) int {
	for i, item := range s {
		if item == v {
			return i
		}
	}
	return -1
}
