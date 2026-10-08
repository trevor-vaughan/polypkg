package schema

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// validManifestJSON returns a syntactically and schema-valid manifest JSON
// string. It is used by the schema-tightening specs below to construct invalid
// variants without touching the Go struct (which cannot carry extra fields).
func validManifestJSON() string {
	return `{
		"schema": "polypkg.manifest/v2",
		"generation": 1,
		"scope": "user",
		"produced_by": {
			"tool": "polypkg",
			"version": "0.1.0",
			"timestamp": "2026-01-01T00:00:00Z",
			"host": "h"
		},
		"entries": [
			{
				"name": "curl",
				"version": "8.0.0",
				"content_hash": "sha256:abc",
				"source_url": "https://example.com/curl"
			}
		]
	}`
}

var _ = Describe("Manifest.Canonicalize", func() {
	It("produces deterministic output across repeated calls", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 42,
			Scope:      "user",
			ProducedBy: ProducedBy{
				Tool:      "polypkg",
				Version:   "0.1.0",
				Timestamp: time.Date(2026, 5, 22, 15, 30, 42, 0, time.UTC),
				Host:      "test",
			},
			Entries: []ManifestEntry{
				{Name: "b", Version: "1.0.0", ContentHash: "sha256:bbb"},
				{Name: "a", Version: "1.0.0", ContentHash: "sha256:aaa"},
			},
		}
		c1, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		c2, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		Expect(c1).To(Equal(c2), "canonicalization must be deterministic")
	})

	It("emits top-level keys in RFC 8785 lexicographic order", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{
				Tool:      "polypkg",
				Version:   "0.1.0",
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Host:      "h",
			},
			Entries: []ManifestEntry{},
		}
		c, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		s := string(c)

		// RFC 8785 requires lexicographic key order. The top-level keys of
		// Manifest are: entries, generation, produced_by, schema, scope.
		Expect(strings.HasPrefix(s, `{"entries":`)).To(BeTrue(),
			"canonical output must start with {\"entries\":, got: %s", s)

		topKeys := []string{`"entries":`, `"generation":`, `"produced_by":`, `"schema":`, `"scope":`}
		prev := -1
		for _, key := range topKeys {
			idx := strings.Index(s, key)
			Expect(idx).To(BeNumerically(">", prev),
				"key %q must appear after previous key; canonical: %s", key, s)
			prev = idx
		}
	})

	It("does not HTML-escape ampersand characters", func() {
		// RFC 8785 forbids HTML escaping; jcs must emit a literal '&'.
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{
				Tool:      "polypkg",
				Version:   "0.1.0",
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Host:      "h",
			},
			Entries: []ManifestEntry{
				{
					Name:        "wget",
					Version:     "1.0.0",
					ContentHash: "sha256:abc",
					SourceURL:   "https://example.com/p?a=1&b=2",
				},
			},
		}

		canonical, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())

		s := string(canonical)
		Expect(s).To(ContainSubstring(`&`),
			"canonical bytes must contain literal & (RFC 8785 forbids HTML escaping)")
		Expect(s).NotTo(ContainSubstring("\\u0026"),
			"canonical bytes must not contain \\u0026 (HTML-escaping of &)")
	})
})

var _ = Describe("ParseManifest", func() {
	It("round-trips a valid manifest through Marshal/Parse", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 5,
			Scope:      "system",
			ProducedBy: ProducedBy{
				Tool:      "polypkg",
				Version:   "0.2.0",
				Timestamp: time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC),
				Host:      "builder.example.com",
			},
			Entries: []ManifestEntry{
				{Name: "curl", Version: "8.0.0", ContentHash: "sha256:abc123"},
			},
		}

		raw, err := json.Marshal(m)
		Expect(err).NotTo(HaveOccurred())

		got, err := ParseManifest(strings.NewReader(string(raw)))
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Schema).To(Equal(m.Schema))
		Expect(got.Generation).To(Equal(m.Generation))
		Expect(got.Scope).To(Equal(m.Scope))
		Expect(got.ProducedBy.Tool).To(Equal(m.ProducedBy.Tool))
		Expect(got.ProducedBy.Version).To(Equal(m.ProducedBy.Version))
		Expect(got.ProducedBy.Host).To(Equal(m.ProducedBy.Host))
		Expect(m.ProducedBy.Timestamp.Equal(got.ProducedBy.Timestamp)).To(BeTrue(),
			"ProducedBy.Timestamp must round-trip: want %v, got %v",
			m.ProducedBy.Timestamp, got.ProducedBy.Timestamp)
		Expect(got.Entries).To(HaveLen(1))
		Expect(got.Entries[0].Name).To(Equal("curl"))
		Expect(got.Entries[0].Version).To(Equal("8.0.0"))
		Expect(got.Entries[0].ContentHash).To(Equal("sha256:abc123"))
	})

	It("rejects a manifest with an invalid scope and one missing required fields", func() {
		// "global" is not in the enum ["system","user"].
		badScope := `{
			"schema": "polypkg.manifest/v2",
			"generation": 1,
			"scope": "global",
			"produced_by": {
				"tool": "polypkg",
				"version": "0.1.0",
				"timestamp": "2026-01-01T00:00:00Z",
				"host": "h"
			},
			"entries": []
		}`
		_, err := ParseManifest(strings.NewReader(badScope))
		Expect(err).To(HaveOccurred())

		missingRequired := `{
			"generation": 1,
			"scope": "user",
			"produced_by": {
				"tool": "polypkg",
				"version": "0.1.0",
				"timestamp": "2026-01-01T00:00:00Z",
				"host": "h"
			},
			"entries": []
		}`
		_, err = ParseManifest(strings.NewReader(missingRequired))
		Expect(err).To(HaveOccurred())
	})

	It("rejects an extra field inside produced_by", func() {
		bad := strings.ReplaceAll(validManifestJSON(),
			`"host": "h"`,
			`"host": "h", "rogue": "x"`,
		)
		_, err := ParseManifest(strings.NewReader(bad))
		Expect(err).To(HaveOccurred(), "extra field in produced_by must be rejected")
	})

	It("rejects an extra field inside an entries item", func() {
		bad := strings.ReplaceAll(validManifestJSON(),
			`"source_url": "https://example.com/curl"`,
			`"source_url": "https://example.com/curl", "rogue": "x"`,
		)
		_, err := ParseManifest(strings.NewReader(bad))
		Expect(err).To(HaveOccurred(), "extra field in entry must be rejected")
	})

	It("rejects a source_url that is not a URI", func() {
		bad := strings.ReplaceAll(validManifestJSON(),
			`"source_url": "https://example.com/curl"`,
			`"source_url": "not a uri"`,
		)
		_, err := ParseManifest(strings.NewReader(bad))
		Expect(err).To(HaveOccurred(), "non-URI source_url must be rejected")
	})

	It("rejects a generation above the I-JSON safe-integer bound", func() {
		// 2^53+1 = 9007199254740993 exceeds the safe-integer bound.
		bad := strings.ReplaceAll(validManifestJSON(),
			`"generation": 1,`,
			`"generation": 9007199254740993,`,
		)
		_, err := ParseManifest(strings.NewReader(bad))
		Expect(err).To(HaveOccurred(), "generation > 2^53-1 must be rejected")
	})

	It("parses an entry with an attestation state", func() {
		doc := strings.ReplaceAll(validManifestJSON(),
			`"source_url": "https://example.com/curl"`,
			`"source_url": "https://example.com/curl", "attestation": {"status": "verified", "predicate_types": ["https://docs.oasis-open.org/sarif/sarif/v2.1.0"], "attestation_hash": "blake3:ab12", "policy_at_install": "warn"}`,
		)
		m, err := ParseManifest(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(m.Entries[0].Attestation).NotTo(BeNil())
		Expect(m.Entries[0].Attestation.Status).To(Equal("verified"))
		Expect(m.Entries[0].Attestation.PolicyAtInstall).To(Equal("warn"))
	})

	It("rejects an attestation state with an unknown status", func() {
		bad := strings.ReplaceAll(validManifestJSON(),
			`"source_url": "https://example.com/curl"`,
			`"source_url": "https://example.com/curl", "attestation": {"status": "tampered", "policy_at_install": "warn"}`,
		)
		_, err := ParseManifest(strings.NewReader(bad))
		Expect(err).To(HaveOccurred(), "unknown attestation status must be rejected")
	})

	It("round-trips a per-source gate-disabled attestation marker", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "0.1.0", Timestamp: time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC), Host: "h"},
			Entries: []ManifestEntry{{
				Name: "hello", Version: "1.0.0", ContentHash: "sha256:abc",
				Attestation: &AttestationState{Status: "unattested", PolicyAtInstall: "off", GateDisabled: true},
			}},
		}
		raw, err := json.Marshal(m)
		Expect(err).NotTo(HaveOccurred())
		got, err := ParseManifest(strings.NewReader(string(raw)))
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Entries[0].Attestation.GateDisabled).To(BeTrue())
	})
})

var _ = Describe("AttestationState carried bindings", func() {
	It("round-trips a bound-unverified carried binding through Canonicalize/ParseManifest", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{
				Tool:      "polypkg",
				Version:   "test",
				Timestamp: time.Unix(0, 0).UTC(),
				Host:      "h",
			},
			Entries: []ManifestEntry{
				{
					Name:        "curl",
					Version:     "8.0.0",
					ContentHash: "blake3:aa",
					Attestation: &AttestationState{
						Status:          "verified",
						PolicyAtInstall: "warn",
						CarriedBindings: []CarriedBinding{
							{
								PredicateType: "https://slsa.dev/provenance/v1",
								Format:        FormatSLSAProvenance,
								SubjectScope:  "artifact",
								Tier:          CarriedTierBoundUnverified,
							},
						},
					},
				},
			},
		}

		canon, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())

		// ParseManifest validates against manifest-v2.json before parsing, so a
		// successful parse proves the additive carried_bindings property is accepted.
		got, err := ParseManifest(bytes.NewReader(canon))
		Expect(err).NotTo(HaveOccurred())

		Expect(got.Entries).To(HaveLen(1))
		Expect(got.Entries[0].Attestation).NotTo(BeNil())
		bindings := got.Entries[0].Attestation.CarriedBindings
		Expect(bindings).To(HaveLen(1))
		Expect(bindings[0].Tier).To(Equal(CarriedTierBoundUnverified))
		Expect(bindings[0].SubjectScope).To(Equal("artifact"))
	})
})

var _ = Describe("AttestationState builder-verified carried binding", func() {
	It("round-trips a builder-verified binding with verifying_key_id through the v2 schema", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "test", Timestamp: time.Unix(0, 0).UTC(), Host: "h"},
			Entries: []ManifestEntry{{
				Name:        "curl",
				Version:     "8.0.0",
				ContentHash: "blake3:aa",
				Attestation: &AttestationState{
					Status:          "verified",
					PolicyAtInstall: "warn",
					CarriedBindings: []CarriedBinding{{
						PredicateType:  "https://slsa.dev/provenance/v1",
						Format:         FormatSLSAProvenance,
						SubjectScope:   "content:bin/curl",
						Tier:           CarriedTierBuilderVerified,
						VerifyingKeyID: "builder-a",
					}},
				},
			}},
		}
		canon, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())

		got, err := ParseManifest(bytes.NewReader(canon))
		Expect(err).NotTo(HaveOccurred())
		b := got.Entries[0].Attestation.CarriedBindings[0]
		Expect(b.Tier).To(Equal(CarriedTierBuilderVerified))
		Expect(b.VerifyingKeyID).To(Equal("builder-a"))
	})

	It("accepts a verified-transport-only binding (no verifying_key_id)", func() {
		m := &Manifest{
			Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "test", Timestamp: time.Unix(0, 0).UTC(), Host: "h"},
			Entries: []ManifestEntry{{
				Name: "curl", Version: "8.0.0", ContentHash: "blake3:aa",
				Attestation: &AttestationState{
					Status: "verified", PolicyAtInstall: "warn",
					CarriedBindings: []CarriedBinding{{
						PredicateType: "https://slsa.dev/provenance/v1",
						Format:        FormatSLSAProvenance,
						SubjectScope:  "artifact",
						Tier:          CarriedTierVerifiedTransportOnly,
					}},
				},
			}},
		}
		canon, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		_, err = ParseManifest(bytes.NewReader(canon))
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("Manifest weak provenance and effective policy", func() {
	It("round-trips weak fields and WeakDepsPolicy through Canonicalize/ParseManifest", func() {
		m := &Manifest{
			Schema:         "polypkg.manifest/v2",
			Generation:     1,
			Scope:          "user",
			WeakDepsPolicy: "on",
			ProducedBy: ProducedBy{
				Tool:      "polypkg",
				Version:   "test",
				Timestamp: time.Unix(0, 0).UTC(),
				Host:      "h",
			},
			Entries: []ManifestEntry{
				{Name: "foo", Version: "1.0.0", ContentHash: "blake3:aa"},
				{Name: "foo-extras", Version: "2.0.0", ContentHash: "blake3:bb", Weak: true, RecommendedBy: []string{"foo"}},
			},
		}

		c1, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())

		got, err := ParseManifest(bytes.NewReader(c1))
		Expect(err).NotTo(HaveOccurred())

		c2, err := got.Canonicalize()
		Expect(err).NotTo(HaveOccurred())

		Expect(bytes.Equal(c1, c2)).To(BeTrue(), "canonicalization must be stable across a parse round-trip")

		weakEntry := got.Entries[1]
		Expect(weakEntry.Weak).To(BeTrue(), "weak flag must survive parse")
		Expect(weakEntry.RecommendedBy).To(HaveLen(1))
		Expect(weakEntry.RecommendedBy[0]).To(Equal("foo"), "RecommendedBy must survive parse")
		Expect(got.WeakDepsPolicy).To(Equal("on"), "WeakDepsPolicy must survive parse")
	})
})

var _ = Describe("AttestationState builder_identity carried binding", func() {
	It("round-trips a builder-verified binding carrying builder_identity through the v2 schema", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "test", Timestamp: time.Unix(0, 0).UTC(), Host: "h"},
			Entries: []ManifestEntry{{
				Name:        "curl",
				Version:     "8.0.0",
				ContentHash: "blake3:aa",
				Attestation: &AttestationState{
					Status:          "verified",
					PolicyAtInstall: "warn",
					CarriedBindings: []CarriedBinding{{
						PredicateType:   "https://slsa.dev/provenance/v1",
						Format:          FormatSLSAProvenance,
						SubjectScope:    "content:bin/curl",
						Tier:            CarriedTierBuilderVerified,
						VerifyingKeyID:  "builder-a",
						BuilderIdentity: "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v8.0.0",
					}},
				},
			}},
		}
		canon, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())

		got, err := ParseManifest(bytes.NewReader(canon))
		Expect(err).NotTo(HaveOccurred())
		b := got.Entries[0].Attestation.CarriedBindings[0]
		Expect(b.BuilderIdentity).To(Equal("https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v8.0.0"))
	})

	It("accepts an in-toto-unclassified binding", func() {
		m := &Manifest{
			Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "test", Timestamp: time.Unix(0, 0).UTC(), Host: "h"},
			Entries: []ManifestEntry{{
				Name: "curl", Version: "8.0.0", ContentHash: "blake3:aa",
				Attestation: &AttestationState{
					Status: "verified", PolicyAtInstall: "warn",
					CarriedBindings: []CarriedBinding{{
						PredicateType: "https://example.com/custom/v1",
						Format:        FormatInTotoUnclassified,
						SubjectScope:  "artifact",
						Tier:          CarriedTierVerifiedTransportOnly,
					}},
				},
			}},
		}
		canon, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		_, err = ParseManifest(bytes.NewReader(canon))
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("AttestationState verified-offline carried binding", func() {
	It("round-trips a verified-offline binding carrying certificate identity + issuer", func() {
		m := &Manifest{
			Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "test", Timestamp: time.Unix(0, 0).UTC(), Host: "h"},
			Entries: []ManifestEntry{{
				Name: "curl", Version: "8.0.0", ContentHash: "blake3:aa",
				Attestation: &AttestationState{
					Status: "verified", PolicyAtInstall: "warn",
					CarriedBindings: []CarriedBinding{{
						PredicateType:       "https://slsa.dev/provenance/v0.2",
						Format:              FormatSigstoreBundle,
						SubjectScope:        "content:bin/curl",
						Tier:                CarriedTierVerifiedOffline,
						CertificateIdentity: "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v8.0.0",
						CertificateIssuer:   "https://token.actions.githubusercontent.com",
					}},
				},
			}},
		}
		canon, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		got, err := ParseManifest(bytes.NewReader(canon))
		Expect(err).NotTo(HaveOccurred())
		b := got.Entries[0].Attestation.CarriedBindings[0]
		Expect(b.Tier).To(Equal(CarriedTierVerifiedOffline))
		Expect(b.CertificateIdentity).To(Equal("https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v8.0.0"))
		Expect(b.CertificateIssuer).To(Equal("https://token.actions.githubusercontent.com"))
	})

	It("round-trips a carried binding with attestation_hash through the v2 schema", func() {
		m := &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "test", Timestamp: time.Unix(0, 0).UTC(), Host: "h"},
			Entries: []ManifestEntry{{
				Name:        "acme",
				Version:     "1.0.0",
				ContentHash: "blake3:deadbeef",
				Attestation: &AttestationState{
					Status:          "verified",
					PolicyAtInstall: "warn",
					CarriedBindings: []CarriedBinding{{
						PredicateType:   "https://slsa.dev/provenance/v1",
						Format:          FormatSLSAProvenance,
						SubjectScope:    "acme.tar.zst",
						Tier:            CarriedTierBuilderVerified,
						AttestationHash: "blake3:deadbeef",
					}},
				},
			}},
		}
		raw, err := json.Marshal(m)
		Expect(err).NotTo(HaveOccurred())
		got, err := ParseManifest(bytes.NewReader(raw))
		Expect(err).NotTo(HaveOccurred())
		b := got.Entries[0].Attestation.CarriedBindings[0]
		Expect(b.AttestationHash).To(Equal("blake3:deadbeef"))
	})
})

var _ = Describe("ManifestEntry platform", func() {
	platformManifest := func(e ManifestEntry) *Manifest {
		return &Manifest{
			Schema:     "polypkg.manifest/v2",
			Generation: 1,
			Scope:      "user",
			ProducedBy: ProducedBy{Tool: "polypkg", Version: "0.1.0", Timestamp: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), Host: "h"},
			Entries:    []ManifestEntry{e},
		}
	}

	It("round-trips a platform-specific entry through Canonicalize/ParseManifest", func() {
		m := platformManifest(ManifestEntry{Name: "rg", Version: "14.1.1", ContentHash: "blake3:ab", Platform: "linux/amd64"})
		raw, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(`"platform":"linux/amd64"`))
		got, err := ParseManifest(bytes.NewReader(raw))
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Entries[0].Platform).To(Equal("linux/amd64"))
	})

	It("omits platform for an agnostic entry so earlier generations canonicalize unchanged", func() {
		m := platformManifest(ManifestEntry{Name: "greet", Version: "1.0.0", ContentHash: "blake3:cd"})
		raw, err := m.Canonicalize()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).NotTo(ContainSubstring(`"platform"`))
	})

	It("reads an entry without platform as platform-agnostic", func() {
		m, err := ParseManifest(strings.NewReader(validManifestJSON()))
		Expect(err).NotTo(HaveOccurred())
		Expect(m.Entries[0].Platform).To(BeEmpty())
	})

	It("accepts a three-segment platform (consumer grammar)", func() {
		doc := strings.ReplaceAll(validManifestJSON(),
			`"source_url": "https://example.com/curl"`,
			`"source_url": "https://example.com/curl", "platform": "linux/arm/v7"`,
		)
		m, err := ParseManifest(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(m.Entries[0].Platform).To(Equal("linux/arm/v7"))
	})

	DescribeTable("rejects a malformed platform",
		func(p string) {
			bad := strings.ReplaceAll(validManifestJSON(),
				`"source_url": "https://example.com/curl"`,
				`"source_url": "https://example.com/curl", "platform": `+strconv.Quote(p),
			)
			_, err := ParseManifest(strings.NewReader(bad))
			Expect(err).To(HaveOccurred(), "platform %q must be rejected", p)
		},
		Entry("path traversal", "../../etc"),
		Entry("upper case", "Linux/amd64"),
		Entry("the reserved any token (absence means any)", "any"),
		Entry("the empty string (absence means any)", ""),
		Entry("a single segment", "linux"),
		Entry("four segments", "linux/arm/v7/x"),
	)
})
