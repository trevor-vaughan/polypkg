package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// attestationProfileYAML renders a minimal valid profile carrying the given
// attestation block (or none when policy is empty).
func attestationProfileYAML(policy string) string {
	src := `
schema: polypkg.spec/v1
name: att
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /tmp/key.pub
`
	if policy != "" {
		src += "attestation:\n  policy: " + policy + "\n"
	}
	return src
}

var _ = Describe("profile attestation policy", func() {
	It("parses attestation: {policy: require}", func() {
		p, err := ParseProfile(strings.NewReader(attestationProfileYAML("require")), "profile.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Attestation).NotTo(BeNil())
		Expect(p.Attestation.Policy).To(Equal("require"))
	})

	It("defaults to an absent attestation block", func() {
		p, err := ParseProfile(strings.NewReader(attestationProfileYAML("")), "profile.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Attestation).To(BeNil())
	})

	It("rejects an unknown policy value", func() {
		_, err := ParseProfile(strings.NewReader(attestationProfileYAML("nonsense")), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})
})
