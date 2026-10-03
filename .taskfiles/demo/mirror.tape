# polypkg — mirroring an upstream repository under your own key. Rendered by
# `task demo:render SCENARIO=mirror`; see .taskfiles/scripts/demo.sh, which
# seeds an upstream repository at ~/upstream and a mirror signing key at
# ~/keys/mirror.key.
#
# The multi-line command is typed with backslash continuations, so the strings
# below use backticks — VHS treats a backslash inside a double-quoted string as
# an escape.
# The Output path here is a placeholder — the Taskfile overrides it with `vhs -o`.
Output "mirror.gif"

Require polypkg

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1200
Set Height 560
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 28ms

Hide
Type `export PS1='$ '; unset NO_COLOR` Enter
Type `cd "$POLYPKG_DEMO_DIR" && clear` Enter
Show

# --- scene 1: pull upstream, re-signing under the local key --------------------
Type `# take an upstream repository offline — re-signed under YOUR key` Enter
Sleep 1.2s
Type `UP=~/upstream/public` Enter
Sleep 400ms
Type `polypkg mirror pull --source-url file://$UP --trust-root $UP/trust_root.pub \` Enter
Type `  --source-name upstream --repo-source mirror \` Enter
Type `  --output-dir ~/mirror --key ~/keys/mirror.key --key-dir ~/cache -o ~/mirror.tar` Enter
Sleep 5s

Hide
Type `clear` Enter
Show

# --- scene 2: verify the bundle before serving it ------------------------------
Type `# check the bundle before you carry it to the air-gapped site` Enter
Sleep 1.2s
Type `polypkg mirror verify ~/mirror.tar` Enter
Sleep 4s
