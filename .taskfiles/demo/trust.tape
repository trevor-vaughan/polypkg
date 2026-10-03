# polypkg — a repository compromise, refused. Rendered by
# `task demo:render SCENARIO=trust`; see .taskfiles/scripts/demo.sh, which pins
# the publisher's key at ~/publisher-key.pub (outside the served directory) and
# stages an attacker-signed copy of the same repository at ~/attacker-repo.
#
# Scene 2 really does overwrite the published tree — nothing here is staged
# output. It works as a demo only because the pinned key lives outside the
# directory being overwritten; see the note in demo.sh.
# The Output path here is a placeholder — the Taskfile overrides it with `vhs -o`.
Output "trust.gif"

Require polypkg

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1200
Set Height 560
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 30ms

Hide
Type `export PS1='$ '; unset NO_COLOR` Enter
Type `cd "$POLYPKG_DEMO_DIR" && clear` Enter
Show

# --- scene 1: a normal install from the publisher you trust --------------------
Type "# at init you pinned one publisher's key; this installs against it" Enter
Sleep 1.2s
Type "polypkg install hello" Enter
Sleep 4.5s

Hide
Type "clear" Enter
Show

# --- scene 2: the repository is re-signed under someone else's key -------------
Type "# simulate a compromise: replace the published tree with an attacker's" Enter
Sleep 1.2s
Type "cp -a ~/attacker-repo/public/. ~/repo/public/" Enter
Sleep 1.5s
Type "polypkg upgrade" Enter
Sleep 4s

# --- scene 3: refused, and what you already had is untouched -------------------
Type "# refused — and the package you already had is still there" Enter
Sleep 1.2s
Type "polypkg list" Enter
Sleep 3.5s
