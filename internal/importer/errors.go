package importer

import (
	"errors"
	"fmt"
	"strings"
)

// ErrFetchTrustedRoot is wrapped, with the cause, by Run's error when
// Options.TrustedRoot fails.
var ErrFetchTrustedRoot = errors.New("fetch the Sigstore trusted root")

// LookupError wraps the error of one of Run's two GitHub lookups: Lookup is
// "release" (the release itself) or "repository" (its metadata). Only these
// two requests decide whether the release exists; a 404 anywhere else is
// returned without one.
type LookupError struct {
	Lookup string
	Err    error
}

func (e *LookupError) Error() string { return e.Err.Error() }
func (e *LookupError) Unwrap() error { return e.Err }

// TargetExistsError refuses an import whose output directory for a platform
// already exists. Dir is that directory, joined to Options.OutDir.
type TargetExistsError struct {
	Dir string
}

func (e *TargetExistsError) Error() string {
	return fmt.Sprintf("%s already exists; refusing to overwrite it (remove it to import again)", e.Dir)
}

// CaseVariantError refuses an import because Dir already holds Existing, a
// directory whose name differs from Want only in letter case. What is
// "package" when Want is the package name (Dir is Options.OutDir) and
// "version" when Want is the version (Dir is OutDir/<name>). On a
// case-insensitive filesystem the two would share a directory, and repo build
// refuses to publish both.
type CaseVariantError struct {
	Dir, Existing, Want, What string
}

func (e *CaseVariantError) Error() string {
	return fmt.Sprintf("%q already holds %q, which differs from the %s %q only in letter case; "+
		"a case-insensitive filesystem would merge them, and repo build refuses to publish both",
		e.Dir, e.Existing, e.What, e.Want)
}

// ProvenanceError refuses an import because SLSA provenance GitHub returned
// for an asset does not verify against the Sigstore trusted root. Index and
// Total place the attestation among those returned for Asset; Reason is
// sigstore-go's explanation, which can echo bundle contents.
type ProvenanceError struct {
	Asset        string
	Index, Total int
	Reason       string
}

func (e *ProvenanceError) Error() string {
	return fmt.Sprintf("provenance attestation %d of %d for %s %v", e.Index, e.Total, e.Asset, &verifyFailure{reason: e.Reason})
}

// BinError refuses a --bin value: Bin is not a command name the path action
// can expose, or, when Repeated, it is given twice.
type BinError struct {
	Bin      string
	Repeated bool
}

func (e *BinError) Error() string {
	if e.Repeated {
		return fmt.Sprintf("--bin %q is given twice", e.Bin)
	}
	return fmt.Sprintf("--bin %q is not a command name: a command name is letters, digits, '_' and '-'", e.Bin)
}

// NameError refuses a package name that is not a package-name slug. FromRepo
// is set when the name was derived from the repository name because no
// --name was given. Err is schema.ValidatePackageName's error.
type NameError struct {
	Name     string
	FromRepo bool
	Err      error
}

func (e *NameError) Error() string {
	if e.FromRepo {
		return fmt.Sprintf("the repository name, lower-cased as %q, is not a valid package name", e.Name)
	}
	return fmt.Sprintf("%q is not a valid package name", e.Name)
}

func (e *NameError) Unwrap() error { return e.Err }

// VersionError refuses a version that is not a semantic version usable as a
// directory name. FromTag is set when it is the release tag, read because no
// --version was given.
type VersionError struct {
	Version string
	FromTag bool
}

func (e *VersionError) Error() string {
	if e.FromTag {
		return fmt.Sprintf("release tag %q is not a semantic version", e.Version)
	}
	return fmt.Sprintf("version %q is not a semantic version", e.Version)
}

// NoPlatformError is Run's error when every platform was dropped. Reasons
// lists each drop as "<os>/<arch>: <reason>"; the error also wraps each
// drop's cause, so a caller can tell, for example, that a platform had no
// integrity source (ghrelease.ErrUnverifiable).
type NoPlatformError struct {
	Owner, Repo, Version string
	Reasons              []string
	causes               []error
}

func (e *NoPlatformError) Error() string {
	return fmt.Sprintf("no platform of %s/%s %s could be imported: %s",
		e.Owner, e.Repo, e.Version, strings.Join(e.Reasons, "; "))
}

func (e *NoPlatformError) Unwrap() []error { return e.causes }
