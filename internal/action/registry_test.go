package action

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// expectedActions is the authoritative list of actions the Registry must declare —
// no more, no fewer. This is the anti-drift guard: it MUST be updated in
// lockstep with the Registry map whenever an action is added or removed.
var expectedActions = []string{
	"install",
	"symlink",
	"dir",
	"perms",
	"config",
	"unmanaged",
	"state",
	"path",
	"alternatives",
	"completion",
	"desktop",
	"mime",
	"extract",
}

// expectedFilePlacing is an INDEPENDENT anti-drift oracle for the
// behavior-critical FilePlacing column: the value IsFilePlacing will later
// read from the Registry. It is written out by hand — NOT derived from the
// Registry — so an action that silently defaults FilePlacing to false (or an
// unintended flip) is caught here rather than slipping through. Update it in
// lockstep with the Registry whenever an action is added, removed, or changes
// its file-placing behavior.
var expectedFilePlacing = map[string]bool{
	"install":      true,
	"symlink":      true,
	"dir":          true,
	"perms":        true,
	"config":       true,
	"unmanaged":    true,
	"state":        true,
	"path":         true,
	"alternatives": true,
	"completion":   true,
	"desktop":      true,
	"mime":         true,
	"extract":      true,
}

var _ = Describe("Registry", func() {
	It("declares exactly the expected 13 actions", func() {
		keys := make([]string, 0, len(Registry))
		for name := range Registry {
			keys = append(keys, name)
		}
		Expect(keys).To(ConsistOf(expectedActions))
	})

	It("declares the expected FilePlacing value for every action", func() {
		placingKeys := make([]string, 0, len(expectedFilePlacing))
		for name := range expectedFilePlacing {
			placingKeys = append(placingKeys, name)
		}
		registryKeys := make([]string, 0, len(Registry))
		for name := range Registry {
			registryKeys = append(registryKeys, name)
		}
		// The oracle must cover exactly the same actions as the Registry, so a
		// new action forces an explicit FilePlacing choice here.
		Expect(placingKeys).To(ConsistOf(registryKeys))

		for name, want := range expectedFilePlacing {
			Expect(Registry[name].FilePlacing).To(Equal(want),
				"FilePlacing for action %q must match the independent oracle", name)
		}
	})

	It("reports IsFilePlacing per the independent oracle", func() {
		for name, want := range expectedFilePlacing {
			Expect(IsFilePlacing(name)).To(Equal(want),
				"IsFilePlacing(%q) must match the independent oracle", name)
		}
		Expect(IsFilePlacing("does-not-exist")).To(BeFalse(),
			"IsFilePlacing must report false for an unknown action")
	})

	It("is well-formed for every entry", func() {
		for key, spec := range Registry {
			Expect(spec.Name).To(Equal(key), "Spec.Name must equal its map key for %q", key)
			Expect((spec.Handler != nil) != (spec.MultiHandler != nil)).To(BeTrue(),
				"exactly one of Handler and MultiHandler must be set for %q", key)

			declared := make(map[string]bool, len(spec.Params))
			for _, p := range spec.Params {
				Expect(declared).ToNot(HaveKey(p.Name), "duplicate param %q in action %q", p.Name, key)
				declared[p.Name] = true

				if p.Kind == KindEnum {
					Expect(p.Enum).ToNot(BeEmpty(), "KindEnum param %q in action %q must have a non-empty Enum", p.Name, key)
				}
				if p.Pattern != "" {
					_, err := regexp.Compile(p.Pattern)
					Expect(err).ToNot(HaveOccurred(), "Pattern for param %q in action %q must compile", p.Name, key)
				}
			}

			for _, c := range spec.Constraints {
				if c.Kind == Unsupported {
					// Unsupported names params that must NOT be declared.
					for _, other := range c.Others {
						Expect(declared).ToNot(HaveKey(other),
							"Unsupported constraint in action %q names declared param %q", key, other)
					}
					continue
				}
				if c.Param != "" {
					Expect(declared).To(HaveKey(c.Param),
						"constraint Param %q in action %q must name a declared param", c.Param, key)
				}
				for _, other := range c.Others {
					Expect(declared).To(HaveKey(other),
						"constraint Other %q in action %q must name a declared param", other, key)
				}
			}
		}
	})
})
