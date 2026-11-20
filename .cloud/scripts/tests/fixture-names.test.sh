#!/bin/sh
# Fails on a manifest or lockfile stored under its real name in the umbrella's fixture folders,
# which GitHub would scan for vulnerable dependencies (docs/adr/0014-fixtures-are-stored-renamed.md).
# Usage: sh .cloud/scripts/tests/fixture-names.test.sh
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

folders=".cloud/scripts/measure/baseline-project scripts/benchmark/fixtures"
names="package.json package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml composer.json composer.lock"

failed=0
for folder in $folders; do
	if [ ! -d "$root/$folder" ]; then
		echo "FAIL $folder: fixture folder is missing"
		failed=$((failed + 1))
		continue
	fi
	for name in $names; do
		found=$(cd "$root" && find "$folder" -type f -name "$name")
		for f in $found; do
			echo "FAIL $f: rename it to $f.fixture"
			failed=$((failed + 1))
		done
	done
done

if [ "$failed" -eq 0 ]; then
	echo "ok   no fixture folder holds a real manifest or lockfile name"
fi
[ "$failed" -eq 0 ]
