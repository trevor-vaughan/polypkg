package runner

import (
	"github.com/trevor-vaughan/polypkg/internal/drift"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// decide maps a drift entry + flags + (optional) accepted-overrides to the
// action taken: "healed" | "refused" | "preserved" | "accepted". A path is
// "accepted" only when its accepted snapshot still matches what we observed.
// The "preserved" action (notify_preserve policy) is consumed by the runner's
// checkDrift to build the config action's preserveActions map.
func decide(d drift.Entry, healDrift bool, accepted *schema.AcceptedDrift) string {
	if acceptedMatches(d, accepted) {
		return "accepted"
	}
	switch d.Owned.DriftPolicy {
	case "refuse":
		if healDrift {
			return "healed"
		}
		return "refused"
	case "notify_preserve":
		return "preserved"
	default:
		// notify_heal, silent_heal, or any unknown — treat as healed (the swap overwrites).
		return "healed"
	}
}

func acceptedMatches(d drift.Entry, a *schema.AcceptedDrift) bool {
	if a == nil {
		return false
	}
	ap, ok := a.Paths[d.Owned.Path]
	if !ok {
		return false
	}
	switch d.Reason {
	case drift.ReasonContent:
		return d.Observed == ap.Expected.ContentHash
	case drift.ReasonTarget:
		return d.Observed == ap.Expected.Target
	case drift.ReasonMode:
		return d.Observed == ap.Expected.Mode
	case drift.ReasonFileType:
		return d.Observed == ap.Expected.FileType
	default: // ReasonMissing — never auto-accept absence
		return false
	}
}
