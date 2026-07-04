package cli

import (
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// effectiveWeakPolicy applies precedence flag > profile > default(on). The
// --no-recommends flag forces WeakOff for this invocation; otherwise an absent
// profile block defaults to on and a present block honors its Install field.
//
// Correctness note: the branch `profile != nil && !profile.Install` relies on
// the profile JSON Schema requiring `install` when the recommends block is
// present (see jsonschema/profile-v1.json, "recommends" → "required":
// ["install"]). That constraint means a false Install value always came from
// an explicit `install: false` in the profile, never from Go's zero-value on
// an empty block — ParseProfile rejects `recommends: {}` before the struct is
// returned, so this function never observes that state.
func effectiveWeakPolicy(profile *schema.RecommendsPolicy, noRecommends bool) resolver.WeakPolicy {
	if noRecommends {
		return resolver.WeakOff
	}
	if profile != nil && !profile.Install {
		return resolver.WeakOff
	}
	return resolver.WeakOn
}
