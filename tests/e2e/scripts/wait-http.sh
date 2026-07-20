#!/bin/sh
# Poll the repo-server's published trust root until it serves, or time out.
# Usage: wait-http.sh <url> [attempts]
set -eu
url="$1"
attempts="${2:-30}"
i=0
while [ "$i" -lt "$attempts" ]; do
  if python3 -c "import sys,urllib.request; urllib.request.urlopen('$url', timeout=2)" 2>/dev/null; then
    echo "ready: $url"
    exit 0
  fi
  i=$((i + 1))
  sleep 1
done
echo "timeout waiting for $url" >&2
exit 1
