#!/bin/sh
# Poll until a file exists and is non-empty, or time out.
# Usage: wait-file.sh <path> [attempts]
set -eu
path="$1"
attempts="${2:-30}"
i=0
while [ "$i" -lt "$attempts" ]; do
  if [ -s "$path" ]; then
    echo "ready: $path"
    exit 0
  fi
  i=$((i + 1))
  sleep 1
done
echo "timeout waiting for $path" >&2
exit 1
