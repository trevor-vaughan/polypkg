package attest

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"lukechampine.com/blake3"
)

// digestStrength maps the digest algorithms polypkg can recompute to their bit
// strength. Only these algorithms can participate in a binding. sha1/md5 are
// deliberately absent and forbidden (see below); any other unlisted algorithm
// is "unknown" — it cannot be computed, so it can neither create nor break a
// binding and is simply ignored.
var digestStrength = map[string]int{
	"sha256": 256,
	"blake3": 256,
	"sha512": 512,
}

// forbiddenDigest is the set of broken algorithms whose mere presence in a
// subject is rejected: they are a downgrade vector, so polypkg refuses a
// subject that offers one rather than silently ignoring it: any binding
// ambiguity must fail closed, never fail open into "verified".
var forbiddenDigest = map[string]bool{"sha1": true, "md5": true} // DevSkim: ignore DS126858 -- names refused, never used to hash

// MatchSubjectDigests verifies that data hashes to the digests a provenance
// subject claims, and that the binding rests on at least one algorithm at/above
// floor. It recomputes, from data, every SUPPORTED algorithm the subject lists
// and requires each to match; a mismatch on any computed algorithm is tamper
// (reject). A forbidden weak algorithm (sha1/md5) in the subject is rejected
// outright. Unknown (uncomputable) algorithms are ignored — they can neither
// create nor break a binding. A subject with no supported algorithm at/above
// floor is unbindable and rejected (fail closed: the caller treats an
// unbindable carried subject as absent). Claimed hex is compared
// case-insensitively; subject values are BARE hex (no "algo:" prefix). Both the
// subject's algorithm names and floor are matched case-insensitively.
func MatchSubjectDigests(data []byte, subject map[string]string, floor string) error {
	if len(subject) == 0 {
		return errors.New("subject has no digests")
	}
	floorRank, ok := digestStrength[strings.ToLower(floor)]
	if !ok {
		return fmt.Errorf("invalid digest floor %q", floor)
	}
	matchedAtFloor := false
	for rawAlgo, claimedHex := range subject {
		algo := strings.ToLower(rawAlgo)
		if forbiddenDigest[algo] {
			return fmt.Errorf("subject offers forbidden weak digest algorithm %q", algo)
		}
		rank, supported := digestStrength[algo]
		if !supported {
			// Unknown algorithm: cannot recompute, so it cannot verify — ignore
			// it. Binding must rest on a supported algorithm (checked below).
			continue
		}
		got := computeDigest(algo, data)
		if !strings.EqualFold(got, claimedHex) {
			return fmt.Errorf("subject %s digest mismatch: computed %s, claimed %s", algo, got, strings.ToLower(claimedHex))
		}
		if rank >= floorRank {
			matchedAtFloor = true
		}
	}
	if !matchedAtFloor {
		return fmt.Errorf("subject has no digest at or above floor %q that polypkg can verify", floor)
	}
	return nil
}

// Target is one candidate the carried provenance may cover: a scope label
// ("artifact" or "content:<path>") and the exact bytes to hash. Callers
// assemble targets from whatever is authoritative at their binding point —
// pack time from the source content tree, install time from the extracted tree.
type Target struct {
	Scope string
	Bytes []byte
}

// BindSubjects binds each carried subject, BY DIGEST, to the first target whose
// bytes satisfy that subject at the sha256 floor, returning one LinkMaterial per
// bound subject. Selection is by digest, never by name (threat G5). It is
// fail-closed via MatchSubjectDigests: a subject with any mismatching supported
// digest, a forbidden weak algorithm (sha1/md5), or no digest at/above the floor
// does not bind. It errors if NO subject binds — the provenance describes
// nothing among the targets, and the caller must refuse.
func BindSubjects(subjects []Subject, targets []Target) ([]LinkMaterial, error) {
	var materials []LinkMaterial
	for _, s := range subjects {
		for _, t := range targets {
			if MatchSubjectDigests(t.Bytes, s.Digest, "sha256") == nil {
				materials = append(materials, LinkMaterial{Name: t.Scope, Digest: s.Digest})
				break // this subject bound; move to the next subject
			}
		}
	}
	if len(materials) == 0 {
		return nil, errors.New("carried attestation binds nothing: no subject digest matches any target")
	}
	return materials, nil
}

// computeDigest returns the bare-hex digest of data under a supported algorithm.
// It is only called for algorithms present in digestStrength.
func computeDigest(algo string, data []byte) string {
	switch algo {
	case "sha256":
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	case "sha512":
		s := sha512.Sum512(data)
		return hex.EncodeToString(s[:])
	case "blake3":
		h := blake3.New(32, nil)
		_, _ = h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	default:
		return ""
	}
}
