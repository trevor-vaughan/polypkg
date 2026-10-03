# polypkg — publishing a newer version and upgrading to it. Rendered by
# `task demo:render SCENARIO=upgrade`; see .taskfiles/scripts/demo.sh, which
# installs hello 1.0.0 and stages the 1.1.0 package source at ~/hello-1.1.0.
#
# Note for maintainers: this tape does NOT show an exact pin being "held back",
# which the README describes. `repo add` keys polypkg-repo.yaml by package NAME,
# so publishing 1.1.0 replaces 1.0.0 and an exact pin becomes unsatisfiable
# rather than held back. Add that beat if a repository can ever serve two
# versions of one package.
# The Output path here is a placeholder — the Taskfile overrides it with `vhs -o`.
Output "upgrade.gif"

Require polypkg

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1200
Set Height 460
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 30ms

Hide
Type `export PS1='$ '; unset NO_COLOR` Enter
Type `cd "$POLYPKG_DEMO_DIR" && clear` Enter
Show

# --- scene 1: what is installed today -----------------------------------------
Type "polypkg list" Enter
Sleep 2.5s

# --- scene 2: the publisher ships 1.1.0 ---------------------------------------
Type "# meanwhile, the publisher releases 1.1.0" Enter
Sleep 1.2s
Type "polypkg repo add ~/hello-1.1.0 --manifest ~/repo/polypkg-repo.yaml --key-dir ~/keys" Enter
Sleep 3.5s

Hide
Type "clear" Enter
Show

# --- scene 3: upgrade re-resolves the profile ---------------------------------
Type "# upgrade re-resolves the profile against what the source now offers" Enter
Sleep 1.2s
Type "polypkg upgrade" Enter
Sleep 3.5s
Type "polypkg list" Enter
Sleep 3.5s
