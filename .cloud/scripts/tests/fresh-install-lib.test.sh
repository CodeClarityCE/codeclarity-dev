#!/bin/sh
# Tests that no script sourcing fresh-install/lib.sh defines a function lib.sh also defines,
# since the definition sourced last silently replaces the other, and that its login works
# against the current release and the one before ADR 0025.
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

work=$(mktemp -d)
functions "$lib" >"$work/lib-functions"
grep -rl 'fresh-install/lib.sh' "$root/.cloud/scripts" --include='*.sh' >"$work/scripts"
while read -r script; do
	[ "$script" = "$lib" ] && continue
	case "$script" in *.test.sh) continue ;; esac
	shared=$(functions "$script" | comm -12 "$work/lib-functions" -)
	name=${script#"$root"/}
	if [ -z "$shared" ]; then
		check "$name defines no function lib.sh defines" ok
	else
		check "$name defines no function lib.sh defines (both define: $(echo "$shared" | tr '\n' ' '))" bad
	fi
done <"$work/scripts"
# A curl stand-in: answers the sign-in as $STUB_LOGIN says (cookie, body or fail), and logs every
# other call's -H headers to $work/headers.
mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'EOF'
#!/bin/sh
url=""
headers=""
while [ $# -gt 0 ]; do
	case "$1" in
	-H) headers="$headers$2
"; shift ;;
	-X | -d | -o | -D | -w | --cacert | --form-string | -F) shift ;;
	http*) url=$1 ;;
	esac
	shift
done
case "$url" in
*/auth/authenticate)
	case "$STUB_LOGIN" in
	cookie) printf 'HTTP/1.1 201 Created\r\nset-cookie: __Host-Http-cc_access=new-access; Path=/; HttpOnly; Secure; SameSite=Strict\r\n\r\n{"data":{"token_expiry":"x"}}' ;;
	body) printf 'HTTP/1.1 201 Created\r\ncontent-type: application/json\r\n\r\n{"data":{"token":"old-access","token_expiry":"x"}}' ;;
	*) exit 22 ;;
	esac
	;;
*) printf '%s' "$headers" >"$STUB_HEADERS" ;;
esac
EOF
chmod +x "$work/bin/curl"

# Logs in with the stub answering as $1, then makes one get; prints the token and the headers sent.
login_and_get() {
	(
		PATH="$work/bin:$PATH" STUB_LOGIN=$1 STUB_HEADERS="$work/headers" API_BASE=https://stub
		LOGIN_EMAIL=a@example.com LOGIN_PASSWORD=p
		export PATH STUB_LOGIN STUB_HEADERS API_BASE LOGIN_EMAIL LOGIN_PASSWORD
		# shellcheck source=/dev/null
		. "$lib"
		token=$(login)
		: >"$work/headers"
		[ -z "$token" ] || get /org >/dev/null
		echo "token=$token"
		cat "$work/headers"
	)
}

out=$(login_and_get cookie)
case "$out" in *"Cookie: __Host-Http-cc_access=new-access"*"X-CodeClarity-CSRF: 1"*) r=ok ;; *) r=bad ;; esac
case "$out" in *Authorization*) r=bad ;; esac
check "a release that sets cookies is called on the access cookie with the CSRF header (got: $(echo "$out" | tr '\n' ' '))" $r

out=$(login_and_get body)
case "$out" in *"Authorization: Bearer old-access"*) r=ok ;; *) r=bad ;; esac
case "$out" in *Cookie:*) r=bad ;; esac
check "a release before ADR 0025, which answers the token in the body, is called with it as a bearer (got: $(echo "$out" | tr '\n' ' '))" $r

out=$(login_and_get fail)
[ "$out" = "token=" ] && r=ok || r=bad
check "a failed login prints no token (got: $(echo "$out" | tr '\n' ' '))" $r

rm -rf "$work"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
