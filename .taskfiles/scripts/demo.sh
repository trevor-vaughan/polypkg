#!/usr/bin/env bash
#
# Render a polypkg demo tape into a GIF.
#
# Every scenario records against a throwaway tree under $(mktemp -d) — never the
# maintainer's real profile. polypkg installs packages, writes generation
# history, and links commands into $HOME/.local/bin; a demo that ran against the
# real HOME would mutate all three. The sandbox redirects HOME and every XDG
# directory, so the recorded shell cannot read or write real polypkg state.
#
# Usage: demo.sh <root_dir> <scenario> <tape> <output_gif>
#   root_dir     repository root (used to locate ./cmd/polypkg)
#   scenario     quickstart | trust | drift | publish | mirror | upgrade
#   tape         absolute path to the .tape file to render
#   output_gif   absolute path to write the finished GIF to
#
# Requires on PATH: go, vhs, ttyd, ffmpeg.
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: demo.sh <root_dir> <scenario> <tape> <output_gif>" >&2
	exit 2
fi

ROOT_DIR=$1
SCENARIO=$2
TAPE=$3
OUTPUT_GIF=$4

# Prefer a repo-local vhs in ./bin if one was installed there, while still
# honouring a system-wide vhs already on PATH.
export PATH="$ROOT_DIR/bin:$PATH"

# go.mod pins a Go floor newer than some distro toolchains; let Go fetch it
# rather than failing the render. Respect an explicit override.
: "${GOTOOLCHAIN:=auto}"
export GOTOOLCHAIN

for tool in go vhs ttyd ffmpeg; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "demo.sh: '$tool' not found on PATH" >&2
		exit 1
	}
done

[[ -f "$TAPE" ]] || {
	echo "demo.sh: tape not found: $TAPE" >&2
	exit 1
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/polypkg-demo.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# The recorded shell's home. Everything the demo can see or touch lives here.
DEMO_HOME="$WORK/home"
mkdir -p "$DEMO_HOME" "$WORK/bin"

# Build polypkg fresh into $WORK/bin — outside DEMO_HOME, so a tape that lists
# the home directory shows only demo state and not the binary under test.
(cd "$ROOT_DIR" && go build -o "$WORK/bin/polypkg" ./cmd/polypkg)

# The signing-key password for every repository the sandbox creates. Throwaway
# by construction: the key it protects is generated inside $WORK and deleted
# with it. polypkg refuses a bare password flag, so this goes via the
# environment, which is also how the tapes' `repo add` steps authenticate.
export POLYPKG_REPO_KEY_PASSWORD='demo-pw'

# Sandbox isolation. HOME and all four XDG directories are redirected before any
# polypkg command runs, so nothing here can reach the real profile at
# ~/.config/polypkg or the real generation store.
export HOME="$DEMO_HOME"
export XDG_CONFIG_HOME="$DEMO_HOME/.config"
export XDG_DATA_HOME="$DEMO_HOME/.local/share"
export XDG_STATE_HOME="$DEMO_HOME/.local/state"
export XDG_CACHE_HOME="$DEMO_HOME/.cache"

# polypkg links commands into ~/.local/bin. Putting it on PATH up front keeps
# the "not on your $PATH" advisory out of the recording and lets a tape actually
# run what it just installed.
export PATH="$WORK/bin:$DEMO_HOME/.local/bin:$PATH"

PX="$WORK/bin/polypkg"

# Scaffold a package source at $1 with name $2 and version $3.
seed_package() {
	"$PX" pkg init --name "$2" --version "$3" "$1" >/dev/null
}

# Build a signed repository at $1 under source name $2, with its signing key in
# $3, publishing the package sources listed from $4 onward. The trust root lands
# at $1/public/trust_root.pub and clients install from file://$1/public.
seed_repo() {
	local dir=$1 source=$2 keydir=$3
	shift 3
	"$PX" repo init "$dir" --source "$source" --key-dir "$keydir" >/dev/null
	local src
	for src in "$@"; do
		"$PX" repo add "$src" --manifest "$dir/polypkg-repo.yaml" --key-dir "$keydir" >/dev/null
	done
}

# Point the sandbox profile at the repository at $1 under source name $2.
seed_profile() {
	"$PX" init --scope user --source-name "$2" \
		--source-url "file://$1/public" \
		--trust-root-file "$1/public/trust_root.pub" >/dev/null
}

case "$SCENARIO" in
quickstart)
	# The tape types init, search, install, attestation report, list, status and
	# rollback itself. All it needs is a repository to install from.
	seed_package "$WORK/src/hello" hello 1.0.0
	seed_repo "$DEMO_HOME/repo" demo "$DEMO_HOME/keys" "$WORK/src/hello"
	;;
trust)
	# A compromise in place: the tape installs from the legitimate publisher,
	# then visibly replaces that publisher's published tree with one re-signed
	# under an attacker's key, and shows the next fetch refused.
	#
	# The pinned trust root is copied to ~/publisher-key.pub, OUTSIDE the served
	# directory, and that placement is the whole point. A trust root left inside
	# the directory it validates is not pinned at all: the same overwrite that
	# swaps the signatures swaps the key they are checked against, and the
	# install succeeds. `init --trust-root-file` accepts such a path without
	# complaint, so the demo has to model the correct layout deliberately.
	seed_package "$WORK/src/hello" hello 1.0.0
	seed_repo "$DEMO_HOME/repo" demo "$WORK/publisher-keys" "$WORK/src/hello"
	cp "$DEMO_HOME/repo/public/trust_root.pub" "$DEMO_HOME/publisher-key.pub"
	seed_repo "$DEMO_HOME/attacker-repo" demo "$WORK/attacker-keys" "$WORK/src/hello"
	"$PX" init --scope user --source-name demo \
		--source-url "file://$DEMO_HOME/repo/public" \
		--trust-root-file "$DEMO_HOME/publisher-key.pub" >/dev/null
	;;
drift)
	# Drift is only interesting against an already-installed package, so the
	# install happens here and the tape opens on a healthy system.
	seed_package "$WORK/src/hello" hello 1.0.0
	seed_repo "$DEMO_HOME/repo" demo "$DEMO_HOME/keys" "$WORK/src/hello"
	seed_profile "$DEMO_HOME/repo" demo
	"$PX" install hello >/dev/null
	;;
publish)
	# The publishing tape runs the whole author journey on camera — pkg init,
	# repo init, repo add, then a client install — so there is nothing to seed.
	:
	;;
mirror)
	# An upstream repository to pull from, plus a local mirror signing key. The
	# key comes from `repo init` because that is the only command that generates
	# one; its scaffolded directory is otherwise unused, matching how the
	# mirroring docs describe obtaining a key.
	seed_package "$WORK/src/hello" hello 1.0.0
	seed_repo "$DEMO_HOME/upstream" upstream "$WORK/upstream-keys" "$WORK/src/hello"
	"$PX" repo init "$WORK/mirror-seed" --source mirror --key-dir "$DEMO_HOME/keys" >/dev/null
	# mirror pull writes its build cache into --key-dir but does not create it.
	mkdir -p "$DEMO_HOME/cache"
	;;
upgrade)
	# Install 1.0.0 from a repository that only has 1.0.0, and stage the 1.1.0
	# package source in the home directory so the tape can publish it on camera
	# before upgrading.
	seed_package "$WORK/src/hello" hello 1.0.0
	seed_package "$DEMO_HOME/hello-1.1.0" hello 1.1.0
	seed_repo "$DEMO_HOME/repo" demo "$DEMO_HOME/keys" "$WORK/src/hello"
	seed_profile "$DEMO_HOME/repo" demo
	"$PX" install hello >/dev/null
	;;
*)
	echo "demo.sh: unknown scenario '$SCENARIO'" >&2
	echo "         want quickstart|trust|drift|publish|mirror|upgrade" >&2
	exit 2
	;;
esac

# The tapes' hidden preamble reads $POLYPKG_DEMO_DIR to cd into the sandbox; -o
# overrides the tape's placeholder Output path so the GIF lands where the
# Taskfile wants it.
mkdir -p "$(dirname "$OUTPUT_GIF")"
POLYPKG_DEMO_DIR="$DEMO_HOME" vhs -o "$OUTPUT_GIF" "$TAPE"

echo "demo.sh: wrote $OUTPUT_GIF"
