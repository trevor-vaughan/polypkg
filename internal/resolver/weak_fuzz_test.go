package resolver

import (
	"sort"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// resultSignature renders a *Result into a canonical, order-stable string so two
// runs can be compared ELEMENT-WISE (names, versions, weak flag, recommenders,
// skips, suggests) rather than only by install count. Installed is already
// name-sorted by chosenToResolved and RecommendedBy by augmentWeak; the extra
// sorts here defend the oracle against any future reordering in production so a
// determinism regression surfaces as a signature mismatch, not a flaky pass.
func resultSignature(r *Result) string {
	var b strings.Builder
	for _, e := range r.Installed {
		rb := append([]string(nil), e.RecommendedBy...)
		sort.Strings(rb)
		b.WriteString("I|")
		b.WriteString(e.Name)
		b.WriteByte('@')
		b.WriteString(e.Version)
		if e.Weak {
			b.WriteString("|weak|")
		} else {
			b.WriteString("|hard|")
		}
		b.WriteString(strings.Join(rb, ","))
		b.WriteByte('\n')
	}
	for _, s := range r.Skipped {
		rb := append([]string(nil), s.RecommendedBy...)
		sort.Strings(rb)
		b.WriteString("S|")
		b.WriteString(s.Name)
		b.WriteByte('@')
		b.WriteString(s.VersionRange)
		b.WriteByte('|')
		b.WriteString(s.Reason)
		b.WriteByte('|')
		b.WriteString(strings.Join(rb, ","))
		b.WriteByte('\n')
	}
	for _, sg := range r.Suggests {
		b.WriteString("G|")
		b.WriteString(sg.Name)
		b.WriteByte('@')
		b.WriteString(sg.VersionRange)
		b.WriteByte('|')
		b.WriteString(sg.SuggestedBy)
		b.WriteByte('\n')
	}
	return b.String()
}

// FuzzResolveWithWeak builds a small random catalog where some packages
// recommend another by index, then asserts: no panic, the hard closure is
// identical with policy on vs off, and two on-runs agree on install count.
func FuzzResolveWithWeak(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		n := len(b)%6 + 1
		pkgs := map[string][]schema.IndexEntry{}
		name := func(i int) string { return string(rune('a' + i)) }
		for i := 0; i < n; i++ {
			var rec []schema.Relation
			if i < len(b) && b[i]%3 == 0 {
				rec = []schema.Relation{{Name: name(int(b[i]) % n)}}
			}
			pkgs[name(i)] = []schema.IndexEntry{{
				Version: "1.0.0", ContentHash: "blake3:" + name(i), Artifact: name(i),
				Recommends: rec,
			}}
		}
		cat, err := BuildCatalog(&schema.Index{Schema: "polypkg.index/v2", Expires: "2099-01-01T00:00:00Z", Packages: pkgs}, "native")
		if err != nil {
			return
		}
		roots := []Requirement{{Name: name(0)}}
		on, err := ResolveWithWeak(roots, cat, WeakOn)
		if err != nil {
			return
		}
		off, _ := ResolveWithWeak(roots, cat, WeakOff)
		hard := func(r *Result) map[string]bool {
			m := map[string]bool{}
			for _, e := range r.Installed {
				if !e.Weak {
					m[e.Name] = true
				}
			}
			return m
		}
		ho, hf := hard(on), hard(off)
		if len(ho) != len(hf) {
			t.Fatalf("hard closure changed by policy: on=%v off=%v", ho, hf)
		}
		again, _ := ResolveWithWeak(roots, cat, WeakOn)
		if sig, sigAgain := resultSignature(on), resultSignature(again); sig != sigAgain {
			t.Fatalf("nondeterministic result:\nfirst:\n%s\nsecond:\n%s", sig, sigAgain)
		}
	})
}
