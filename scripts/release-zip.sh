#!/bin/sh
# Builds dist/<plugin>-<version>.zip - the file a Claude Code catalogue installs with
# {"source": "archive", "url": ".../releases/download/v<version>/<plugin>-<version>.zip", "sha256": ...}.
#
#   sh scripts/release-zip.sh [<tag or commit>]     (default HEAD)
#
# Why a zip and not git (02.10.2026): a plugin source of type `url`/`github` makes Claude Code run
# `git clone`, and a beginner's Linux or a fresh Mac has no git (on a Mac `git` is the stub that pops
# Apple's developer-tools window). An `archive` source needs only HTTPS. The zip is attached to the
# GitHub release, and a release asset never changes after upload - unlike the zip GitHub builds on
# the fly from a tag, whose bytes (and so its sha256) are not promised to stay the same.
#
# Inside: one top folder `<plugin>-<version>/` holding the plugin root (Claude Code accepts the root
# at the top of the zip or one folder down, and a person who double-clicks the zip gets one folder,
# not twenty files). Taken by `git archive` from the commit, so only committed files go in; the
# tests and the GitHub workflow stay out - they are for the repository, not for the person.
# The release workflow (.github/workflows/release.yml) runs this on every `v*` tag.
set -eu
cd "$(dirname "$0")/.."
ref=${1:-HEAD}
manifest=$(git show "$ref:.claude-plugin/plugin.json")
field() { printf '%s' "$manifest" | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }
name=$(field name)
version=$(field version)
case "$ref" in
  v*) [ "$ref" = "v$version" ] || { echo "release-zip: tag $ref, but plugin.json at it says $version" >&2; exit 1; } ;;
esac
mkdir -p dist
out="dist/$name-$version.zip"
rm -f "$out"
git archive --format=zip -9 --prefix="$name-$version/" -o "$out" "$ref" -- . \
  ':(exclude).github' ':(exclude)tests'
if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$out" | cut -d' ' -f1)
else sum=$(shasum -a 256 "$out" | cut -d' ' -f1); fi
printf '%s  %s\n' "$sum" "$name-$version.zip" > "$out.sha256"
echo "$out"
echo "sha256 $sum"
