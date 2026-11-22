#!/bin/sh
# Tests the deployment support bundle: it writes an archive and prints its path, the archive holds
# versions, configuration, recent error logs and error reports, and no secret value gets into it.
# Uses a stand-in docker that answers from files this test writes.
# Usage: sh .cloud/scripts/tests/support-bundle.test.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
DEPLOYMENT_DIR=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
script="$DEPLOYMENT_DIR/scripts/support-bundle.sh"
[ -f "$script" ] || { echo "no $script; set DEPLOYMENT_DIR to a deployment checkout" >&2; exit 1; }

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$work/out" 2>/dev/null
	fi
}

# Secret values the stand-in stack holds, made at run time; none may appear in a bundle.
random_hex() {
	printf '%s-%s' "$1" "$(date +%s%N)" | sha256sum | cut -d' ' -f1
}
PG_PASSWORD=$(random_hex pg)
AMQP_PASSWORD=$(random_hex amqp)
COOKIE=$(random_hex cookie)
JWT_LINE=$(random_hex jwt)$(random_hex jwt2)
MAIL_PASSWORD="mail p@ss w/ spaces & \$igns $(random_hex mail | cut -c1-8)"
CLICKUP_SECRET=clickup-$(random_hex clickup)
TLS_LINE=$(random_hex tls)
# PEM armour, split so the source holds no key-shaped text.
ARMOUR=-----

mkdir -p "$work/bin" "$work/stack"
cat >"$work/bin/docker" <<'EOF'
#!/bin/sh
# Stand-in docker: answers the bundle's calls from the files in STUB_DIR.
echo "$*" >>"$STUB_DIR/docker.log"
[ "$1" = compose ] || { [ "$1" = version ] && echo 27.5.1 && exit 0; exit 1; }
shift
for arg; do last=$arg; done
case " $* " in
*" version "*) echo 2.32.4 ;;
*" config "*) cat "$STUB_DIR/config.yaml" ;;
*" images "*) cat "$STUB_DIR/images.txt" ;;
*" ps "*"{{.Service}}"*) cut -d' ' -f1 "$STUB_DIR/ps.txt" ;;
*" ps "*) cat "$STUB_DIR/ps.txt" ;;
*" run "*" generate-secrets "*)
	[ -f "$STUB_DIR/secrets-fail" ] && { echo "cannot start generate-secrets" >&2; exit 1; }
	cat "$STUB_DIR/secrets.txt"
	;;
*" logs "*) cat "$STUB_DIR/logs/$last" 2>/dev/null ;;
*) echo "docker stub: unexpected compose $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$work/bin/docker"
PATH="$work/bin:$PATH"
STUB_DIR=$work/stack
export PATH STUB_DIR

# A stand-in instance: its Compose directory, resolved config, containers, logs and secrets volume.
make_stack() {
	rm -rf "$work/deploy" "$work/stack" "$work/bundles"
	mkdir -p "$work/deploy" "$work/stack/logs" "$work/bundles"
	cat >"$work/deploy/docker-compose.yaml" <<'EOF'
x-release-version: &release-version "v0.1.0-beta"
services: {}
EOF
	printf 'CODECLARITY_VERSION=v0.1.0-beta\nDOMAIN=ci.example.com\nMAIL_AUTH_PASSWORD="%s"\nNVD_API_KEY=\n' \
		"$MAIL_PASSWORD" >"$work/deploy/.env"
	cat >"$work/stack/config.yaml" <<EOF
name: codeclarity
services:
  api:
    environment:
      DOMAIN: ci.example.com
      MAIL_AUTH_PASSWORD: $MAIL_PASSWORD
      CLICKUP_CLIENT_SECRET: $CLICKUP_SECRET
      NVD_API_KEY: ""
      PG_DB_HOST: pgbouncer
    image: codeclarityce/api:v0.1.0-beta
  service-dispatcher:
    environment:
      AMQP_URL: amqps://codeclarity:$AMQP_PASSWORD@rabbitmq:5671/
    image: codeclarityce/service-dispatcher:v0.1.0-beta
configs:
  tls-key:
    content: |
      ${ARMOUR}BEGIN PRIVATE KEY$ARMOUR
      $TLS_LINE
      ${ARMOUR}END PRIVATE KEY$ARMOUR
EOF
	cat >"$work/stack/images.txt" <<'EOF'
CONTAINER                         REPOSITORY                         TAG           IMAGE ID       SIZE
codeclarity-api-1                 codeclarityce/api                  v0.1.0-beta   0123456789ab   300MB
codeclarity-service-dispatcher-1  codeclarityce/service-dispatcher   v0.1.0-beta   ba9876543210   20MB
EOF
	cat >"$work/stack/ps.txt" <<'EOF'
api running healthy
service-dispatcher running
db running healthy
EOF
	cat >"$work/stack/logs/api" <<EOF
{"level":"info","service":"api","time":"2026-11-22T10:00:00Z","msg":"api started"}
{"level":"error","service":"api","time":"2026-11-22T10:01:00Z","msg":"database refused password $PG_PASSWORD"}
{"level":"error","service":"frontend","time":"2026-11-22T10:02:00Z","msg":"Cannot read the SBOM page","fields":{"route":"/sbom","source":"frontend"}}
{"level":"warn","service":"frontend","time":"2026-11-22T10:03:00Z","msg":"Slow chart render","fields":{"source":"frontend"}}
EOF
	cat >"$work/stack/logs/service-dispatcher" <<EOF
{"level":"info","msg":"dispatcher ready","time":"2026-11-22T10:00:00Z"}
{"level":"error","msg":"amqp dial failed for amqps://codeclarity:$AMQP_PASSWORD@rabbitmq:5671/","time":"2026-11-22T10:05:00Z"}
EOF
	cat >"$work/stack/logs/db" <<'EOF'
2026-11-22 10:00:00.000 UTC [1] LOG:  database system is ready to accept connections
2026-11-22 10:06:00.000 UTC [42] FATAL:  password authentication failed for user "cc_api"
EOF
	# What the bundle reads from the secrets volume: every view and the store.
	cat >"$work/stack/secrets.txt" <<EOF
POSTGRES_PASSWORD='$PG_PASSWORD'
AMQP_PASSWORD='$AMQP_PASSWORD'
COOKIE_SECRET='$COOKIE'
$PG_PASSWORD
${ARMOUR}BEGIN EC PRIVATE KEY$ARMOUR
$JWT_LINE
${ARMOUR}END EC PRIVATE KEY$ARMOUR
EOF
}

# Runs the bundle in the stand-in Compose directory, writing into $work/bundles.
bundle() {
	(cd "$work/deploy" && sh "$script" "$work/bundles") >"$work/out" 2>&1
}

# Extracts the one archive in $work/bundles into $work/x.
extract() {
	rm -rf "$work/x"
	mkdir -p "$work/x"
	set -- "$work"/bundles/*.tar.gz
	[ $# = 1 ] && [ -f "$1" ] && tar -xzf "$1" -C "$work/x"
}

# Every file of the extracted bundle, concatenated.
contents() {
	find "$work/x" -type f -exec cat {} +
}

test_it_writes_the_archive_and_prints_its_path() {
	make_stack
	result=ok
	bundle || result=bad
	set -- "$work"/bundles/*.tar.gz
	[ $# = 1 ] && [ -f "$1" ] || result=bad
	[ "$(tail -n 1 "$work/out")" = "$1" ] || result=bad
	case $1 in "$work/bundles/codeclarity-support-"*.tar.gz) ;; *) result=bad ;; esac
	check "it writes one archive and prints its path last" $result
}

test_the_archive_holds_versions_config_error_logs_and_error_reports() {
	make_stack
	result=ok
	bundle || result=bad
	extract || result=bad
	contents >"$work/all" 2>/dev/null
	grep -q 'v0.1.0-beta' "$work/x"/*/versions.txt || result=bad
	grep -q 'codeclarityce/service-dispatcher' "$work/x"/*/versions.txt || result=bad
	grep -q '2.32.4' "$work/x"/*/versions.txt || result=bad
	grep -q 'PG_DB_HOST: pgbouncer' "$work/x"/*/config.yaml || result=bad
	grep -q 'DOMAIN: ci.example.com' "$work/x"/*/config.yaml || result=bad
	grep -q 'service-dispatcher running' "$work/x"/*/containers.txt || result=bad
	grep -q 'amqp dial failed' "$work/x"/*/logs/service-dispatcher.log || result=bad
	grep -q 'password authentication failed' "$work/x"/*/logs/db.log || result=bad
	grep -q 'api started' "$work/x"/*/logs/api.log && result=bad
	grep -q 'Cannot read the SBOM page' "$work/x"/*/error-reports.log || result=bad
	grep -q 'Slow chart render' "$work/x"/*/error-reports.log || result=bad
	grep -q 'database refused' "$work/x"/*/error-reports.log && result=bad
	check "the archive holds versions, config, containers, error logs per service and error reports" $result
}

test_no_secret_value_gets_into_the_archive() {
	make_stack
	result=ok
	bundle || result=bad
	extract || result=bad
	contents >"$work/all" 2>/dev/null
	[ -s "$work/all" ] || result=bad
	for secret in "$PG_PASSWORD" "$AMQP_PASSWORD" "$COOKIE" "$JWT_LINE" "$MAIL_PASSWORD" "$CLICKUP_SECRET" "$TLS_LINE"; do
		if grep -qF -- "$secret" "$work/all"; then
			echo "secret in bundle: $secret" >>"$work/out"
			result=bad
		fi
	done
	grep -q '\[REDACTED\]' "$work/all" || result=bad
	# An unset secret stays visibly empty, so the bundle still shows it is not set.
	grep -q 'NVD_API_KEY: ""' "$work/x"/*/config.yaml || result=bad
	check "no secret value from the secrets volume, .env or config gets into the archive" $result
}

test_without_the_secrets_volume_it_still_redacts_by_name_and_warns() {
	make_stack
	: >"$work/stack/secrets-fail"
	result=ok
	bundle || result=bad
	extract || result=bad
	contents >"$work/all" 2>/dev/null
	for secret in "$MAIL_PASSWORD" "$CLICKUP_SECRET" "$TLS_LINE" "$AMQP_PASSWORD"; do
		grep -qF -- "$secret" "$work/all" && result=bad
	done
	grep -qi 'secrets volume' "$work/out" || result=bad
	check "without the secrets volume it still redacts secrets by name and says so" $result
}

test_it_fails_outside_a_deployment_directory() {
	make_stack
	rm "$work/deploy/docker-compose.yaml"
	result=ok
	bundle && result=bad
	[ -z "$(ls "$work/bundles")" ] || result=bad
	check "outside a directory with docker-compose.yaml it fails and writes nothing" $result
}

test_it_writes_the_archive_and_prints_its_path
test_the_archive_holds_versions_config_error_logs_and_error_reports
test_no_secret_value_gets_into_the_archive
test_without_the_secrets_volume_it_still_redacts_by_name_and_warns
test_it_fails_outside_a_deployment_directory

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
