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

	It("parses a per-source attestation block with require and a key allow-list", func() {
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
    attestation:
      require:
        - https://slsa.dev/provenance/v1
      builders:
        allow:
          - key: dGVzdC1wdWJrZXk=
          - sigstore:
              issuer: https://token.actions.githubusercontent.com
              san: https://github.com/org/repo/.github/workflows/build.yml@*
`
		p, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).NotTo(HaveOccurred())
		sb := p.Sources.Sources["native"]
		Expect(sb.Attestation).NotTo(BeNil())
		Expect(sb.Attestation.Require).To(ConsistOf("https://slsa.dev/provenance/v1"))
		Expect(sb.Attestation.Builders).NotTo(BeNil())
		Expect(sb.Attestation.Builders.Allow).To(HaveLen(2))
		Expect(sb.Attestation.Builders.Allow[0].Key).To(Equal("dGVzdC1wdWJrZXk="))
		Expect(sb.Attestation.Builders.Allow[1].Sigstore).NotTo(BeNil())
		Expect(sb.Attestation.Builders.Allow[1].Sigstore.Issuer).To(Equal("https://token.actions.githubusercontent.com"))
	})

	It("rejects an allow-list entry carrying both key and sigstore", func() {
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
    attestation:
      builders:
        allow:
          - key: dGVzdA==
            sigstore:
              issuer: i
              san: s
`
		_, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})

	It("rejects a bare '*' SAN (match-anything defeats the allow-list)", func() {
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
    attestation:
      builders:
        allow:
          - sigstore:
              issuer: i
              san: '*'
`
		_, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})

	It("rejects an unknown property in the per-source attestation block", func() {
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
    attestation:
      bogus: true
`
		_, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})

	It("parses a per-source attestation block with tier: off", func() {
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
    attestation:
      tier: off
`
		p, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).NotTo(HaveOccurred())
		sb := p.Sources.Sources["native"]
		Expect(sb.Attestation).NotTo(BeNil())
		Expect(sb.Attestation.Tier).To(Equal("off"))
	})

	It("rejects an unknown tier value (fail closed)", func() {
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
    attestation:
      tier: bogus
`
		_, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})

	It("rejects tier: off combined with require (contradictory)", func() {
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
    attestation:
      tier: off
      require:
        - https://slsa.dev/provenance/v1
`
		_, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})

	It("rejects tier: off combined with builders (contradictory)", func() {
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
    attestation:
      tier: off
      builders:
        allow:
          - key: dGVzdA==
`
		_, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).To(HaveOccurred())
	})
})
