package cli

import (
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestEffectiveWeakPolicy(t *testing.T) {
	on := true
	off := false
	cases := []struct {
		name      string
		profile   *schema.RecommendsPolicy
		noRecFlag bool
		want      resolver.WeakPolicy
	}{
		{"default (no block, no flag) is on", nil, false, resolver.WeakOn},
		{"profile install:false suppresses", &schema.RecommendsPolicy{Install: off}, false, resolver.WeakOff},
		{"profile install:true installs", &schema.RecommendsPolicy{Install: on}, false, resolver.WeakOn},
		{"flag overrides default-on", nil, true, resolver.WeakOff},
		{"flag overrides profile-on", &schema.RecommendsPolicy{Install: on}, true, resolver.WeakOff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := effectiveWeakPolicy(c.profile, c.noRecFlag)
			if got != c.want {
				t.Fatalf("effectiveWeakPolicy(%+v, %v) = %v, want %v", c.profile, c.noRecFlag, got, c.want)
			}
		})
	}
}
