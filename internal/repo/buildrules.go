package repo

import (
	"fmt"
	"maps"
	"slices"

	"github.com/trevor-vaughan/polypkg/internal/platform"
)

// entryRules enforces repo build's per-name publishing rules across every
// manifest entry for one package name. The index lists a name's entries as
// (version, platform) pairs, and a client selects the entries whose platform is
// empty (platform-agnostic) or equal to its host, so:
//
//   - a (version, platform) pair may be declared once: a second entry would
//     shadow the first and the repository would stop matching its manifest;
//   - a version is either one platform-agnostic artifact or one artifact per
//     platform, never both: with both, a host matching a platform entry would
//     see two candidates for one version;
//   - a declared platform must pass producer validation, so a typo such as
//     linux/amd46 fails the build instead of publishing an entry no host can
//     match. pkg lint applies the same check, but --skip-attestations builds
//     and prebuilt entries never run lint.
type entryRules struct {
	name string
	// seen maps version -> platform ("" for platform-agnostic) -> the manifest
	// identifier (source path or prebuilt artifact path) that declared it.
	seen map[string]map[string]string
}

// admit records that the manifest entry identified by src builds version for
// plat ("" for platform-agnostic), or returns a *PublishError naming the rule
// the entry breaks. prebuilt reports that src is a prebuilt artifact, whose
// embedded polypkg.yaml is signed and cannot be edited, rather than a source
// tree; it selects the remedy the refusal suggests. A refused entry is not
// recorded.
func (r *entryRules) admit(version, plat, src string, prebuilt bool) error {
	if plat != "" {
		if err := platform.ValidateProducer(plat); err != nil {
			hint := "set platform: in the package's polypkg.yaml (" + src + ") to an os/arch pair listed by " +
				"`go tool dist list` (for example linux/amd64), or remove it to publish a platform-agnostic artifact"
			if prebuilt {
				hint = "the prebuilt artifact " + src + " declares this platform in its embedded polypkg.yaml, " +
					"which cannot be edited: rebuild it from a source whose polypkg.yaml sets platform: to an " +
					"os/arch pair listed by `go tool dist list` (for example linux/amd64), " +
					"or delete its entry from polypkg-repo.yaml"
			}
			return &PublishError{
				Msg: fmt.Sprintf("package %q version %s declares platform %q, which repo build cannot publish",
					r.name, version, plat),
				Hint: hint,
				Err:  err,
			}
		}
	}

	byPlat := r.seen[version]
	if prevSrc, dup := byPlat[plat]; dup {
		if plat == "" {
			return &PublishError{
				Msg: fmt.Sprintf("package %q version %s is declared twice: %s and %s",
					r.name, version, prevSrc, src),
				Hint: "each entry under a package name must build a distinct version; " +
					"`polypkg repo remove " + r.name + "@" + version + "` withdraws every build of this version, " +
					"so to drop only one of these entries, delete it from polypkg-repo.yaml",
			}
		}
		return &PublishError{
			Msg: fmt.Sprintf("package %q version %s for platform %s is declared twice: %s and %s",
				r.name, version, plat, prevSrc, src),
			Hint: "each entry for one version must declare a distinct platform: in its polypkg.yaml; " +
				"`polypkg repo remove " + r.name + "@" + version + "` withdraws every platform's build of this version, " +
				"so to withdraw only one platform, delete its entry from polypkg-repo.yaml",
		}
	}

	var mixed bool
	var agnosticSrc, platSrc, platName string
	if prevSrc, ok := byPlat[""]; ok {
		mixed = true
		agnosticSrc, platSrc, platName = prevSrc, src, plat
	} else if plat == "" && len(byPlat) > 0 {
		mixed = true
		platName = slices.Sorted(maps.Keys(byPlat))[0]
		agnosticSrc, platSrc = src, byPlat[platName]
	}
	if mixed {
		return &PublishError{
			Msg: fmt.Sprintf("package %q version %s has both a platform-agnostic entry (%s) and a %s entry (%s)",
				r.name, version, agnosticSrc, platName, platSrc),
			Hint: "a version is either one platform-agnostic artifact or one artifact per platform: " +
				"give every entry for this version a platform (set platform: in a source's polypkg.yaml; " +
				"rebuild a prebuilt artifact from such a source), or keep only the platform-agnostic entry",
		}
	}

	if byPlat == nil {
		byPlat = map[string]string{}
		r.seen[version] = byPlat
	}
	byPlat[plat] = src
	return nil
}
