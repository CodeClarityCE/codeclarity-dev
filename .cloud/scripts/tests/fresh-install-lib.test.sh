#!/bin/sh
# Tests that no script sourcing fresh-install/lib.sh defines a function lib.sh also defines,
# since the definition sourced last silently replaces the other.
# Usage: sh .cloud/scripts/tests/fresh-install-lib.test.sh
root=$(cd "$(dirname "$0")/../../.." && pwd)
lib="$root/.cloud/scripts/tests/fresh-install/lib.sh"
passed=0 failed=0

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
	fi
}

# Prints the names of the functions a script defines, one per line, sorted.
functions() {
	sed -n 's/^\([a-z_][a-z0-9_]*\)() *{.*/\1/p' "$1" | sort -u
}

functions "$lib" >"${TMPDIR:-/tmp}/lib-functions.$$"
for script in $(grep -rl 'fresh-install/lib.sh' "$root/.cloud/scripts" --include='*.sh'); do
	[ "$script" = "$lib" ] && continue
	case "$script" in *.test.sh) continue ;; esac
	shared=$(functions "$script" | comm -12 "${TMPDIR:-/tmp}/lib-functions.$$" -)
	name=${script#"$root"/}
	if [ -z "$shared" ]; then
		check "$name defines no function lib.sh defines" ok
	else
		check "$name defines no function lib.sh defines (both define: $(echo "$shared" | tr '\n' ' '))" bad
	fi
done
rm -f "${TMPDIR:-/tmp}/lib-functions.$$"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
