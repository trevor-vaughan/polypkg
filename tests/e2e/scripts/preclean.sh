#!/bin/sh
# Run the compose teardown quietly before an e2e run.
#
# Usage: preclean.sh <log-path> <teardown command...>
#
# On a host with no e2e stack running, `podman-compose down -v` prints one
# `Error: no container with name or ID "e2e_<svc>_1" found` line per service —
# nine lines that look like a failing suite before any test has started — and
# still exits 0. Capture the transcript to <log-path> rather than the terminal,
# and print it only when the teardown genuinely fails, so a real error is
# reported rather than swallowed.
set -eu

log="$1"
shift

mkdir -p "$(dirname "$log")"

if "$@" >"$log" 2>&1; then
	exit 0
fi

echo "error: pre-run teardown failed; transcript follows ($log)" >&2
cat "$log" >&2
exit 1
