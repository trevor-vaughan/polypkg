package resolver

import (
	"fmt"
	"strings"
)

// FailureKind classifies why resolution failed.
type FailureKind int

// FailureKind values enumerate the distinct reasons resolution can fail.
const (
	KindNoCandidate FailureKind = iota // no candidate satisfies a requirement
	KindConflict                       // every candidate conflicts with the current selection
	KindTooComplex                     // resolution exceeded its step budget
	KindUnknownName                    // the package name is absent from every source
	KindNoVersion                      // the name exists, but no version matches the constraint
)

// maxAvailableShown caps how many candidate versions a KindNoVersion message
// enumerates so a package with hundreds of releases does not flood the
// terminal. The full set is retained on ResolveError.Available for callers
// that want it; only the rendered string is capped.
const maxAvailableShown = 8

// ResolveError is a structured, human-readable resolution failure.
type ResolveError struct {
	Kind        FailureKind
	Requirement Requirement // the requirement that could not be satisfied
	Path        []string    // requirement-name chain from a root to here
	Detail      string      // extra context (e.g. the conflicting package)
	Available   []string    // for KindNoVersion: known versions, newest first
}

// Transitive reports whether the failed requirement was introduced by a
// dependency rather than required directly by the profile. A root requirement
// has a single-element path (just its own name); anything longer arrived via a
// parent. Callers use this to decide whether the "(required via ...)" chain is
// meaningful — for a direct requirement it would only repeat the package name.
func (e *ResolveError) Transitive() bool {
	return len(e.Path) > 1
}

func (e *ResolveError) Error() string {
	var b strings.Builder
	switch e.Kind {
	case KindUnknownName:
		fmt.Fprintf(&b, "package %q not found in any configured source", e.Requirement.Name)
	case KindNoVersion:
		fmt.Fprintf(&b, "package %q has no version matching %q (available: %s)",
			e.Requirement.Name, e.Requirement.VersionRange, availableList(e.Available))
	case KindNoCandidate:
		fmt.Fprintf(&b, "no candidate satisfies %q", reqString(e.Requirement))
	case KindConflict:
		fmt.Fprintf(&b, "cannot satisfy %q without a conflict", reqString(e.Requirement))
	case KindTooComplex:
		fmt.Fprintf(&b, "resolution too complex while resolving %q (step budget exceeded)", reqString(e.Requirement))
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Detail)
	}
	// Keep the provenance chain only when the requirement is transitive; for a
	// directly-required package it would merely repeat the name.
	if e.Transitive() {
		fmt.Fprintf(&b, " (required via %s)", strings.Join(e.Path, " -> "))
	}
	return b.String()
}

// availableList renders the version list for a KindNoVersion message, capping
// at maxAvailableShown and summarizing the remainder as "+ N more".
func availableList(versions []string) string {
	if len(versions) <= maxAvailableShown {
		return strings.Join(versions, ", ")
	}
	shown := strings.Join(versions[:maxAvailableShown], ", ")
	return fmt.Sprintf("%s, + %d more", shown, len(versions)-maxAvailableShown)
}

func reqString(r Requirement) string {
	if r.VersionRange == "" {
		return r.Name
	}
	return r.Name + " " + r.VersionRange
}
