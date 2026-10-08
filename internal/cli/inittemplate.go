package cli

import (
	"fmt"
	"regexp"
	"strings"
)

// profileTemplate is the commented profile template written by `polypkg init`.
// It mirrors the README quickstart example with every field annotated so a
// new user can orient themselves without opening documentation.
//
// Placeholders: {NAME}, {SCOPE}, {SCOPE_COMMENT}, {SOURCE_NAME}, {SOURCE_URL},
// {TRUST_ROOT_PATH}.
// The scope name is parameterized so `init --scope system` writes a profile that
// actually defines the system scope it is placed for: a profile under
// /etc/polypkg that declared only the user scope could never be applied with
// `--scope system`.
const profileTemplate = `# polypkg profile: the single source of truth for what's installed.
# Edit this file to add or remove packages, then run:
#   polypkg plan    (preview changes)
#   polypkg apply   (apply them)
schema: polypkg.spec/v1

# A short identifier for this machine (alphanumerics, hyphens, underscores).
name: {NAME}

scopes:
  {SCOPE}:                # {SCOPE_COMMENT}
    substrate: store      # content-store backend (the default and recommended choice)

sources:
  order: [{SOURCE_NAME}]         # consult sources in this order when resolving packages
  {SOURCE_NAME}:
    type: polypkg-native
    # URL of the package repository.
    url: {SOURCE_URL}
    # Path to the repository's minisign public key (.pub file).
    # Obtain this from your repository operator.
    trust_root: {TRUST_ROOT_PATH}

# Attestation posture for newly fetched packages (docs/trust-policy.md, "Attestation policy").
# A present-but-invalid attestation is always refused, in every mode; this
# knob only governs packages published with NO attestation:
#   warn (default) — install unattested packages with a warning
#   require        — refuse unattested packages
#   off            — install unattested packages silently
# attestation:
#   policy: require

# packages:
#   {SCOPE}:
#     # Add packages here once the repo is reachable.  Examples:
#     #   hello:
#     #     version: ">=1.0.0"   # any 1.x or newer
#     #     version: "=1.2.3"    # pin exactly
#     #     version: "*"         # latest available
`

// hostNamePattern matches valid polypkg name characters.
var hostNamePattern = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// fillProfileTemplate substitutes hostname, sourceName, sourceURL, and
// trustRootPath into profileTemplate and returns the rendered string. hostname
// is sanitized to the schema's ^[a-zA-Z0-9_-]+$ pattern; an empty or
// all-invalid hostname falls back to "my-machine". An empty or unrecognized
// scope falls back to "user". sourceName is validated upstream
// (validateSourceName) before it reaches this function.
//
// All placeholders are replaced in a single simultaneous pass via
// strings.NewReplacer so that a value containing another placeholder (e.g. a
// --source-url that literally contains "{TRUST_ROOT_PATH}") is never
// re-scanned and expanded.
func fillProfileTemplate(hostname, sourceName, sourceURL, trustRootPath, scope string) string {
	name := hostNamePattern.ReplaceAllString(hostname, "-")
	// Trim any leading/trailing hyphens left by the replacement.
	name = strings.Trim(name, "-")
	if name == "" {
		name = "my-machine"
	}
	scopeComment := "installs under your home directory; no root required"
	if scope == "system" {
		scopeComment = "installs machine-wide; requires root"
	} else {
		scope = "user"
	}
	return strings.NewReplacer(
		"{NAME}", name,
		"{SCOPE}", scope,
		"{SCOPE_COMMENT}", scopeComment,
		"{SOURCE_NAME}", sourceName,
		"{SOURCE_URL}", sourceURL,
		"{TRUST_ROOT_PATH}", trustRootPath,
	).Replace(profileTemplate)
}

// quickstartText is the success block appended after "wrote <path>" in text mode.
const quickstartText = `
next steps:
  polypkg search <name>     find a package
  polypkg install <name>    install it
  polypkg status            see what's applied
`

// formatQuickstart formats the success message for text mode.
func formatQuickstart(writtenPath string) string {
	return fmt.Sprintf("wrote %s\n%s", writtenPath, quickstartText)
}
