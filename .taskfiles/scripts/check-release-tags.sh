#!/usr/bin/env bash
#
# Refuse to release while the repository holds a tag that is not a SemVer
# `v` tag: v followed by a SemVer 2.0.0 version, vMAJOR.MINOR.PATCH with an
# optional -pre-release and +build suffix (v1.2.3, v1.2.3-rc.1, v1.2.3+build.5).
#
# goreleaser takes the release version from the newest tag verbatim and starts
# the changelog at the tag before it. Checkpoint or scratch tags created by
# local tooling (a name like checkpoint/20260725-000356) corrupt both: as the
# newest tag such a name puts a "/" into every artifact name, and as the
# previous tag it cuts the release notes down to the commits made after it.
# Every tag is checked, not only the newest, because any of them can become
# the previous tag.
#
# Usage: check-release-tags.sh   (run from inside the repository)
set -euo pipefail

# SemVer 2.0.0: numeric identifiers have no leading zeros; pre-release and
# build suffixes are dot-separated, non-empty identifiers, and a numeric
# pre-release identifier has no leading zero either.
num='(0|[1-9][0-9]*)'
pre_id="($num|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
build_id='[0-9A-Za-z-]+'
# Bracket expressions rather than backslashes: awk -v interprets escapes.
semver="^v${num}[.]${num}[.]${num}(-${pre_id}([.]${pre_id})*)?([+]${build_id}([.]${build_id})*)?\$"

stray=$(git tag --list | awk -v re="$semver" '$0 !~ re { print "  " $0 }')

if [[ -n $stray ]]; then
	echo "refusing to release: these tags are not SemVer \`v\` tags (vMAJOR.MINOR.PATCH[-pre-release][+build]):" >&2
	echo "$stray" >&2
	echo "hint: delete a tag that 'git ls-remote --tags origin' does not list with 'git tag -d <tag>'" >&2
	exit 1
fi

echo "release tags ok: every tag is a SemVer \`v\` tag"
