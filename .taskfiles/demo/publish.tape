# polypkg — scaffolding a package and publishing a signed repository. Rendered
# by `task demo:render SCENARIO=publish`; see .taskfiles/scripts/demo.sh, which
# seeds nothing: this tape runs the whole author journey on camera.
#
# The signing-key password comes from POLYPKG_REPO_KEY_PASSWORD, exported by
# demo.sh — polypkg refuses a bare password flag, and a demo should not teach
# typing one.
# The Output path here is a placeholder — the Taskfile overrides it with `vhs -o`.
Output "publish.gif"

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

# --- scene 1: scaffold a package ----------------------------------------------
Type "# scaffold a package; the template is complete enough to publish as-is" Enter
Sleep 1.2s
Type "polypkg pkg init --name hello --version 1.0.0 ./hello" Enter
Sleep 2.5s
Type "polypkg pkg lint ./hello" Enter
Sleep 2.5s

Hide
Type "clear" Enter
Show

# --- scene 2: create a signed repository --------------------------------------
# --key-dir is absolute here because ~ reads clearly on screen, not because it
# has to be. A relative --key-dir used to be recorded verbatim in the manifest
# and then resolved against the manifest directory, so `repo init --key-dir
# ./keys` put the key somewhere `repo add` could not find it; init now records
# the absolute path. Relative paths are fine to demo if a future edit wants them.
Type "# a repository is a directory plus a signing key you keep outside it" Enter
Sleep 1.2s
Type "polypkg repo init ~/myrepo --source demo --key-dir ~/keys" Enter
Sleep 3s

Hide
Type "clear" Enter
Show

# --- scene 3: publish, and see what clients fetch ------------------------------
Type "polypkg repo add ./hello --manifest ~/myrepo/polypkg-repo.yaml --key-dir ~/keys" Enter
Sleep 3.5s
Type "# signed index, signed trust document, content-addressed pool" Enter
Sleep 1.2s
Type "ls ~/myrepo/public" Enter
Sleep 4s
