package schema

import (
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("profile version skew", func() {
	It("names the profile when it declares a newer spec version", func() {
		_, err := ParseProfile(strings.NewReader("schema: polypkg.spec/v2\nname: box\n"), "my-profile.yaml")
		var ne *NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(err.Error()).To(Equal(
			"my-profile.yaml was written by a newer polypkg (polypkg.spec/v2; this version reads v1); upgrade polypkg"))
	})

	It("still reports an ordinary invalid profile with the friendly list", func() {
		_, err := ParseProfile(strings.NewReader("schema: polypkg.spec/v1\nname: box\nbogus: 1\n"), "my-profile.yaml")
		Expect(err).To(MatchError(ContainSubstring("profile my-profile.yaml is invalid:")))
	})
})
