package resolver

import (
	"errors"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("ResolveError shapes", func() {
	Describe("unknown package name", func() {
		It("classifies a name absent from the catalog as KindUnknownName", func() {
			c := build(map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "h", Artifact: "hello-1.0.0.tar.zst"}},
			})
			_, err := Resolve([]Requirement{{Name: "nosuchpkg", VersionRange: "=1.0.0"}}, c)
			var rerr *ResolveError
			Expect(errors.As(err, &rerr)).To(BeTrue())
			Expect(rerr.Kind).To(Equal(KindUnknownName))
			Expect(rerr.Requirement.Name).To(Equal("nosuchpkg"))
			Expect(rerr.Available).To(BeEmpty())
		})

		It("renders a name-focused message without an available list", func() {
			c := build(map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "h", Artifact: "hello-1.0.0.tar.zst"}},
			})
			_, err := Resolve([]Requirement{{Name: "nosuchpkg", VersionRange: "=1.0.0"}}, c)
			Expect(err.Error()).To(ContainSubstring(`package "nosuchpkg" not found in any configured source`))
			Expect(err.Error()).NotTo(ContainSubstring("available"))
		})
	})

	Describe("known name, no matching version", func() {
		It("classifies a present name with no satisfying version as KindNoVersion and lists versions", func() {
			c := build(map[string][]schema.IndexEntry{
				"hello": {
					{Version: "1.0.0", ContentHash: "h", Artifact: "hello-1.0.0.tar.zst"},
					{Version: "1.1.0", ContentHash: "h", Artifact: "hello-1.1.0.tar.zst"},
				},
			})
			_, err := Resolve([]Requirement{{Name: "hello", VersionRange: "=9.9.9"}}, c)
			var rerr *ResolveError
			Expect(errors.As(err, &rerr)).To(BeTrue())
			Expect(rerr.Kind).To(Equal(KindNoVersion))
			Expect(rerr.Requirement.Name).To(Equal("hello"))
			// Newest first.
			Expect(rerr.Available).To(Equal([]string{"1.1.0", "1.0.0"}))
		})

		It("renders a version-focused message with the available list", func() {
			c := build(map[string][]schema.IndexEntry{
				"hello": {
					{Version: "1.0.0", ContentHash: "h", Artifact: "hello-1.0.0.tar.zst"},
					{Version: "1.1.0", ContentHash: "h", Artifact: "hello-1.1.0.tar.zst"},
				},
			})
			_, err := Resolve([]Requirement{{Name: "hello", VersionRange: "=9.9.9"}}, c)
			Expect(err.Error()).To(ContainSubstring(`package "hello" has no version matching "=9.9.9"`))
			Expect(err.Error()).To(ContainSubstring("available: 1.1.0, 1.0.0"))
		})
	})

	Describe("available-version cap", func() {
		It("lists the newest 8 and summarizes the remainder", func() {
			entries := make([]schema.IndexEntry, 0, 12)
			for i := range 12 {
				v := fmt.Sprintf("1.%d.0", i)
				entries = append(entries, schema.IndexEntry{
					Version: v, ContentHash: "h", Artifact: "p-" + v + ".tar.zst",
				})
			}
			c := build(map[string][]schema.IndexEntry{"p": entries})
			_, err := Resolve([]Requirement{{Name: "p", VersionRange: "=9.9.9"}}, c)
			var rerr *ResolveError
			Expect(errors.As(err, &rerr)).To(BeTrue())
			Expect(rerr.Kind).To(Equal(KindNoVersion))
			// All versions retained on the struct (newest first), but the
			// rendered string caps at 8 and notes the remainder.
			Expect(rerr.Available).To(HaveLen(12))
			Expect(rerr.Available[0]).To(Equal("1.11.0"))
			msg := err.Error()
			Expect(msg).To(ContainSubstring("1.11.0, 1.10.0, 1.9.0, 1.8.0, 1.7.0, 1.6.0, 1.5.0, 1.4.0"))
			Expect(msg).To(ContainSubstring("+ 4 more"))
			Expect(msg).NotTo(ContainSubstring("1.3.0"))
		})
	})

	Describe("provenance suffix", func() {
		It("omits (required via ...) for a directly-required package", func() {
			c := build(map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "h", Artifact: "hello-1.0.0.tar.zst"}},
			})
			_, err := Resolve([]Requirement{{Name: "hello", VersionRange: "=9.9.9"}}, c)
			Expect(err.Error()).NotTo(ContainSubstring("required via"))
		})

		It("keeps (required via ...) for a transitively-required package", func() {
			c := build(map[string][]schema.IndexEntry{
				"app": {{Version: "1.0.0", ContentHash: "h", Artifact: "app.tar.zst",
					Depends: []schema.Relation{{Name: "lib", Version: "=9.9.9"}}}},
				"lib": {{Version: "2.0.0", ContentHash: "h", Artifact: "lib.tar.zst"}},
			})
			_, err := Resolve([]Requirement{{Name: "app"}}, c)
			Expect(err.Error()).To(ContainSubstring("required via"))
			Expect(strings.Contains(err.Error(), "app")).To(BeTrue())
		})

		It("omits the suffix for an unknown directly-required package", func() {
			c := build(map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "h", Artifact: "hello-1.0.0.tar.zst"}},
			})
			_, err := Resolve([]Requirement{{Name: "nosuchpkg"}}, c)
			Expect(err.Error()).NotTo(ContainSubstring("required via"))
		})
	})
})
