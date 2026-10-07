package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/platform"
)

// v3Index renders a polypkg.index/v3 document whose "packages" object body is
// pkgs (the text between the braces).
func v3Index(pkgs string) string {
	return `{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{` + pkgs + `}}`
}

// v3Entry renders one index entry; extra is spliced in after the required
// fields (e.g. `,"platform":"linux/amd64"`).
func v3Entry(extra string) string {
	return `{"version":"1.0.0","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst"` + extra + `}`
}

var _ = Describe("ParseIndex polypkg.index/v3", func() {
	It("parses a platform per entry and leaves it empty (platform-agnostic) when absent", func() {
		idx, err := ParseIndex(strings.NewReader(v3Index(
			`"rg":[` + v3Entry(`,"platform":"linux/amd64"`) + `,` + v3Entry(`,"platform":"darwin/arm64"`) + `],` +
				`"greet":[` + v3Entry("") + `]`)))
		Expect(err).NotTo(HaveOccurred())
		Expect(idx.Schema).To(Equal("polypkg.index/v3"))
		Expect(idx.Packages["rg"][0].Platform).To(Equal("linux/amd64"))
		Expect(idx.Packages["rg"][1].Platform).To(Equal("darwin/arm64"))
		Expect(idx.Packages["greet"][0].Platform).To(BeEmpty())
	})

	It("omits an empty platform when an entry is marshalled", func() {
		out, err := json.Marshal(IndexEntry{Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "pool/aa.tar.zst"})
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).NotTo(ContainSubstring("platform"))
	})

	DescribeTable("accepts any well-formed platform, known to this toolchain or not",
		func(p string) {
			_, err := ParseIndex(strings.NewReader(v3Index(`"x":[` + v3Entry(`,"platform":"`+p+`"`) + `]`)))
			Expect(err).NotTo(HaveOccurred())
		},
		Entry("a variant", "linux/arm/v7"),
		Entry("a port this toolchain lacks", "plan9/mips"),
	)

	DescribeTable("refuses a malformed platform",
		func(p string) {
			_, err := ParseIndex(strings.NewReader(v3Index(`"x":[` + v3Entry(`,"platform":"`+p+`"`) + `]`)))
			Expect(err).To(HaveOccurred())
		},
		Entry("explicit empty (absence is the agnostic spelling)", ""),
		Entry("the reserved claim token", "any"),
		Entry("upper case", "Linux/amd64"),
		Entry("one segment", "linux"),
		Entry("four segments", "linux/arm/v7/x"),
		Entry("traversal", "../amd64"),
	)

	DescribeTable("refuses a package key outside the package-name slug",
		func(name string) {
			key, err := json.Marshal(name)
			Expect(err).NotTo(HaveOccurred())
			_, err = ParseIndex(strings.NewReader(v3Index(string(key) + `:[` + v3Entry("") + `]`)))
			Expect(err).To(HaveOccurred(), "package key %q must be refused by the schema", name)
		},
		Entry("traversal", "../../etc/x"),
		Entry("path separator", "a/b"),
		Entry("dot", "py3.11"),
		Entry("empty", ""),
		Entry("YAML injection", "hello\noutput: /tmp/x"),
	)

	DescribeTable("refuses an older index as built by an older polypkg",
		func(found string) {
			_, err := ParseIndex(strings.NewReader(
				`{"schema":"` + found + `","expires":"2099-01-01T00:00:00Z","packages":{}}`))
			var oe *OlderIndexError
			Expect(errors.As(err, &oe)).To(BeTrue(), "got %v", err)
			Expect(oe.Found).To(Equal(found))
			Expect(err.Error()).To(Equal("the repository index is " + found +
				", which an older polypkg built; this polypkg reads only polypkg.index/v3"))
		},
		Entry("v2", "polypkg.index/v2"),
		Entry("v1", "polypkg.index/v1"),
	)

	It("refuses an older index even when it carries fields v3 does not know", func() {
		_, err := ParseIndex(strings.NewReader(
			`{"schema":"polypkg.index/v2","expires":"2099-01-01T00:00:00Z","packages":{},"legacy":true}`))
		var oe *OlderIndexError
		Expect(errors.As(err, &oe)).To(BeTrue(), "got %v", err)
	})

	It("leaves a malformed schema id to strict validation", func() {
		_, err := ParseIndex(strings.NewReader(`{"schema":"polypkg.index/vX","expires":"2099-01-01T00:00:00Z","packages":{}}`))
		Expect(err).To(HaveOccurred())
		var oe *OlderIndexError
		Expect(errors.As(err, &oe)).To(BeFalse(), "got %v", err)
	})

	It("exports the schema identifier it reads, built from its kind and version", func() {
		Expect(IndexSchemaID).To(Equal(fmt.Sprintf("%s/v%d", indexSchemaKind, indexSchemaVersion)))
	})

	It("uses the shared package-name and platform patterns", func() {
		var idx struct {
			Properties struct {
				Packages struct {
					PropertyNames struct {
						Pattern string `json:"pattern"`
					} `json:"propertyNames"`
				} `json:"packages"`
			} `json:"properties"`
			Defs struct {
				Entry struct {
					Properties struct {
						Platform struct {
							Pattern string `json:"pattern"`
						} `json:"platform"`
					} `json:"properties"`
				} `json:"entry"`
			} `json:"$defs"`
		}
		Expect(json.Unmarshal(indexSchemaV3, &idx)).To(Succeed())
		Expect(idx.Properties.Packages.PropertyNames.Pattern).To(Equal(PackageNamePattern))
		Expect(idx.Defs.Entry.Properties.Platform.Pattern).To(Equal(platform.Pattern))
	})
})
