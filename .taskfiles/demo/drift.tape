# polypkg — detecting and reconciling drift. Rendered by
# `task demo:render SCENARIO=drift`; see .taskfiles/scripts/demo.sh, which
# installs hello so the recording opens on a healthy system.
# The Output path here is a placeholder — the Taskfile overrides it with `vhs -o`.
Output "drift.gif"

Require polypkg

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1200
Set Height 520
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 30ms

Hide
Type `export PS1='$ '; unset NO_COLOR` Enter
Type `cd "$POLYPKG_DEMO_DIR" && clear` Enter
Show

# --- scene 1: a healthy system ------------------------------------------------
Type "polypkg status" Enter
Sleep 2.5s

# --- scene 2: something changes the managed tree out of band -------------------
Type "# now something outside polypkg deletes a managed file" Enter
Sleep 1.2s
Type "rm ~/.local/share/polypkg/active/hello/bin/hello" Enter
Sleep 1.5s
Type "polypkg status -vv" Enter
Sleep 4.5s

Hide
Type "clear" Enter
Show

# --- scene 3: apply reconciles ------------------------------------------------
Type "# the profile is still the source of truth, so re-apply it" Enter
Sleep 1.2s
Type "polypkg apply" Enter
Sleep 3s
Type "polypkg status" Enter
Sleep 3.5s
