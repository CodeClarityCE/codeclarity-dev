#!/bin/sh
# Fails when two ADRs share a number, a number is skipped, or an umbrella file links an ADR file that does not exist.
# Usage: sh .cloud/scripts/tests/adr-numbers.test.sh
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
cd "$root" || exit 1

failed=0
expected=1
numbers=$(for f in docs/adr/[0-9][0-9][0-9][0-9]-*.md; do basename "$f" | cut -c1-4; done | sort)
for number in $numbers; do
	n=$(echo "$number" | sed 's/^0*//')
	if [ "$n" -lt "$expected" ]; then
		echo "FAIL ADR $number is used by more than one file"
		failed=$((failed + 1))
		continue
	fi
	while [ "$expected" -lt "$n" ]; do
		echo "FAIL ADR $(printf '%04d' "$expected") is missing: numbers must have no gap"
		failed=$((failed + 1))
		expected=$((expected + 1))
	done
	expected=$((n + 1))
done

# Links to ADR files from tracked umbrella files (submodules are separate repos).
links=$(git grep -ohE 'docs/adr/[0-9]{4}-[A-Za-z0-9-]+\.md' -- . ':!docs/adr/*' 2>/dev/null | sort -u)
links="$links $(cd docs/adr && grep -ohE '\(\./?[0-9]{4}-[A-Za-z0-9-]+\.md\)|\b[0-9]{4}-[a-z0-9-]+\.md' -- *.md | tr -d '()' | sed 's|^\./||; s|^|docs/adr/|' | sort -u)"
for link in $links; do
	if [ ! -f "$link" ]; then
		echo "FAIL $link is linked but does not exist"
		failed=$((failed + 1))
	fi
done

if [ "$failed" -eq 0 ]; then
	echo "ok   ADR numbers are unique and gapless, and every linked ADR file exists"
fi
[ "$failed" -eq 0 ]
