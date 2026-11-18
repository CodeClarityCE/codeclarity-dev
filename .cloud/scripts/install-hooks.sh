#!/bin/sh
# Points core.hooksPath of this checkout and of every submodule, recursively, at the shared .githooks.
# Sets the local config only, with a path relative to each repo, so it works on the host and in the
# devcontainer alike. Usage: make hooks
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
git config --local core.hooksPath .githooks
echo "hooks: . -> .githooks"
# displaypath is relative to $root, so its depth gives the way back up.
# shellcheck disable=SC2016 # git submodule foreach expands these per submodule
git submodule foreach --quiet --recursive '
	up=$(echo "$displaypath" | awk -F/ "{ for (i = 0; i < NF; i++) printf \"../\" }")
	git config --local core.hooksPath "${up}.githooks"
	echo "hooks: $displaypath -> ${up}.githooks"
'
