# polypkg — the quickstart. Rendered by `task demo:quickstart`; see
# .taskfiles/scripts/demo.sh, which pre-seeds a signed file:// repository under
# $POLYPKG_DEMO_DIR/repo and points HOME and every XDG dir at the sandbox.
# The Output path here is a placeholder — the Taskfile overrides it with `vhs -o`.
Output "quickstart.gif"

Require polypkg

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1200
Set Height 560
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 30ms

# --- sandbox setup (hidden): clean prompt, land in the demo home --------------
# VHS sets NO_COLOR in its session and polypkg honours it (lipgloss), so the
# recording would be monochrome without this unset.
Hide
Type `export PS1='$ '; unset NO_COLOR` Enter
Type `cd "$POLYPKG_DEMO_DIR" && clear` Enter
Show

# --- scene 1: point polypkg at a repository -----------------------------------
Type "# describe what should be installed; polypkg makes the system match" Enter
Sleep 1s
Type "REPO=~/repo/public" Enter
Sleep 400ms
Type "polypkg init --source-name demo --source-url file://$REPO --trust-root $REPO/trust_root.pub" Enter
Sleep 2.5s

Hide
Type "clear" Enter
Show

# --- scene 2: the empty baseline ----------------------------------------------
# Applying the profile before installing anything gives generation 1 a known,
# empty state — which is what rollback returns to in scene 5.
Type "# apply the profile as it stands: an empty baseline" Enter
Sleep 900ms
Type "polypkg apply" Enter
Sleep 2.5s

# --- scene 3: install --------------------------------------------------------
Type "# one command: resolve, verify, install, record a new generation" Enter
Sleep 900ms
Type "polypkg install hello" Enter
Sleep 4.5s

Hide
Type "clear" Enter
Show

# --- scene 4: the verification verdict ----------------------------------------
# install prints pipeline stages, not signature verdicts. The evidence polypkg
# recorded at install time is reported by `attestation report` — this is the
# beat that has to be on screen.
#
# `search` is deliberately absent from this tape. On a TTY it opens a
# multi-select picker whose install path cannot succeed: the picker runs inside
# search's withCatalog lock (internal/cli/search.go:68) and the install it
# triggers then fails to take that same lock. Restore that beat once it is fixed.
Type "# every package was signature- and attestation-checked on the way in" Enter
Sleep 900ms
Type "polypkg attestation report" Enter
Sleep 3.5s
Type "polypkg list" Enter
Sleep 2.5s

Hide
Type "clear" Enter
Show

# --- scene 5: rollback is a pointer switch, not a re-download -----------------
Type "polypkg status" Enter
Sleep 2.5s
Type "# every apply is an immutable generation, so undo is one command" Enter
Sleep 1s
Type "polypkg rollback" Enter
Sleep 2.5s
Type "polypkg list" Enter
Sleep 3.5s
