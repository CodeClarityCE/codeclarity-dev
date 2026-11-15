#!/bin/sh
# Tests the production secrets job: it generates every secret once, never overwrites one that
# exists, and lays out what each service reads. Uses the real openssl and a stand-in chown.
# Usage: sh .cloud/scripts/tests/generate-secrets.test.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
DEPLOYMENT_DIR=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
script="$DEPLOYMENT_DIR/scripts/generate-secrets.sh"
[ -f "$script" ] || { echo "no $script; set DEPLOYMENT_DIR to a deployment checkout" >&2; exit 1; }
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_CHOWN_LOG="$work/chowned"
export STUB_CHOWN_LOG

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

generate() {
	sh "$script" "$1" >>"$work/out" 2>&1
}

# Prints a value from a service's env file.
env_value() {
	sed -n "s/^$2='\(.*\)'\$/\1/p" "$1"
}

# Prints a checksum line for every file and its mode, so two snapshots compare whole trees.
snapshot() {
	(cd "$1" && find . -type f | LC_ALL=C sort | while read -r f; do
		printf '%s %s\n' "$(stat -c %a "$f")" "$(sha256sum "$f")"
	done)
}

test_an_empty_volume_gets_every_secret_each_service_reads() {
	: >"$work/out"
	s="$work/fresh"
	result=ok
	generate "$s" || result=bad
	for f in db/env db/ca.crt db/server.crt db/server.key \
		pgbouncer/userlist.txt pgbouncer/ca.crt pgbouncer/server.crt pgbouncer/server.key \
		rabbitmq/env rabbitmq/ca.crt rabbitmq/server.crt rabbitmq/server.key \
		knowledge-restore/env knowledge-restore/ca.crt \
		migrate/.env.prod migrate/ca.crt \
		api/.env.prod api/ca.crt api-jwt/private.pem api-jwt/public.pem \
		service/env service/ca.crt plugin/env plugin/ca.crt knowledge/env knowledge/ca.crt \
		grafana/admin_password grafana/cc_exporter_password grafana/ca.crt \
		exporter/cc_exporter_password exporter/ca.crt; do
		[ -s "$s/$f" ] || {
			echo "missing $f" >>"$work/out"
			result=bad
		}
	done
	check "an empty volume gets every secret each service reads" $result
}

test_a_second_run_changes_nothing() {
	: >"$work/out"
	s="$work/rerun"
	result=ok
	generate "$s" || result=bad
	grep -q 'generated jwt_private.pem' "$work/out" || result=bad
	snapshot "$s" >"$work/before"
	: >"$work/out"
	generate "$s" || result=bad
	snapshot "$s" >"$work/after"
	cmp -s "$work/before" "$work/after" || result=bad
	grep -q 'generated' "$work/out" && result=bad
	check "a second run changes nothing and generates nothing" $result
}

test_an_existing_secret_is_kept_and_missing_ones_are_added() {
	: >"$work/out"
	s="$work/partial"
	mkdir -p "$s/.store"
	printf 'operator-chosen' >"$s/.store/rabbitmq_password"
	result=ok
	generate "$s" || result=bad
	[ "$(cat "$s/.store/rabbitmq_password")" = operator-chosen ] || result=bad
	[ "$(env_value "$s/rabbitmq/env" RABBITMQ_DEFAULT_PASS)" = operator-chosen ] || result=bad
	[ "$(env_value "$s/service/env" AMQP_PASSWORD)" = operator-chosen ] || result=bad
	[ -s "$s/.store/postgres_password" ] || result=bad
	check "an existing secret is kept, used by every service, and missing ones are added" $result
}

test_each_role_gets_its_own_password_and_services_agree_on_it() {
	: >"$work/out"
	s="$work/fresh"
	result=ok
	pw() { env_value "$s/db/env" "$1"; }
	n=$(for v in POSTGRES_PASSWORD CC_API_PASSWORD CC_SERVICE_PASSWORD CC_PLUGIN_PASSWORD \
		CC_KNOWLEDGE_PASSWORD CC_EXPORTER_PASSWORD PGBOUNCER_AUTH_PASSWORD; do pw $v; done | grep -c .)
	distinct=$(for v in POSTGRES_PASSWORD CC_API_PASSWORD CC_SERVICE_PASSWORD CC_PLUGIN_PASSWORD \
		CC_KNOWLEDGE_PASSWORD CC_EXPORTER_PASSWORD PGBOUNCER_AUTH_PASSWORD; do pw $v; done | sort -u | grep -c .)
	[ "$n" = 7 ] || result=bad
	[ "$distinct" = 7 ] || result=bad
	[ "$(env_value "$s/api/.env.prod" PG_DB_PASSWORD)" = "$(pw CC_API_PASSWORD)" ] || result=bad
	[ "$(env_value "$s/service/env" PG_DB_PASSWORD)" = "$(pw CC_SERVICE_PASSWORD)" ] || result=bad
	[ "$(env_value "$s/plugin/env" PG_DB_PASSWORD)" = "$(pw CC_PLUGIN_PASSWORD)" ] || result=bad
	[ "$(env_value "$s/knowledge/env" PG_DB_PASSWORD)" = "$(pw CC_KNOWLEDGE_PASSWORD)" ] || result=bad
	[ "$(env_value "$s/migrate/.env.prod" PG_DB_ADMIN_PASSWORD)" = "$(pw POSTGRES_PASSWORD)" ] || result=bad
	[ "$(env_value "$s/knowledge-restore/env" POSTGRES_PASSWORD)" = "$(pw POSTGRES_PASSWORD)" ] || result=bad
	[ "$(cat "$s/exporter/cc_exporter_password")" = "$(pw CC_EXPORTER_PASSWORD)" ] || result=bad
	[ "$(cat "$s/grafana/cc_exporter_password")" = "$(pw CC_EXPORTER_PASSWORD)" ] || result=bad
	grep -qx "\"pgbouncer_auth\" \"$(pw PGBOUNCER_AUTH_PASSWORD)\"" "$s/pgbouncer/userlist.txt" || result=bad
	[ "$(env_value "$s/api/.env.prod" AMQP_PASSWORD)" = "$(env_value "$s/rabbitmq/env" RABBITMQ_DEFAULT_PASS)" ] || result=bad
	check "each role gets its own password and every service agrees on it" $result
}

test_two_instances_share_no_secret() {
	: >"$work/out"
	result=ok
	generate "$work/other" || result=bad
	for f in "$work"/fresh/.store/*; do
		cmp -s "$f" "$work/other/.store/${f##*/}" && {
			echo "same ${f##*/}" >>"$work/out"
			result=bad
		}
	done
	check "two instances share no secret" $result
}

test_the_certificates_verify_for_the_names_clients_use() {
	: >"$work/out"
	s="$work/fresh"
	result=ok
	for host in db pgbouncer; do
		openssl verify -CAfile "$s/service/ca.crt" -verify_hostname "$host" "$s/pgbouncer/server.crt" >>"$work/out" 2>&1 || result=bad
	done
	openssl verify -CAfile "$s/api/ca.crt" -verify_hostname rabbitmq "$s/rabbitmq/server.crt" >>"$work/out" 2>&1 || result=bad
	openssl verify -CAfile "$s/api/ca.crt" -verify_hostname db "$s/rabbitmq/server.crt" >>"$work/out" 2>&1 && result=bad
	for view in db rabbitmq; do
		[ "$(openssl x509 -in "$s/$view/server.crt" -noout -pubkey | sha256sum)" = \
			"$(openssl pkey -in "$s/$view/server.key" -pubout | sha256sum)" ] || result=bad
	done
	check "the certificates verify for the names clients use and match their keys" $result
}

test_the_jwt_keys_are_a_pair() {
	: >"$work/out"
	s="$work/fresh"
	result=ok
	[ "$(openssl ec -in "$s/api-jwt/private.pem" -pubout 2>/dev/null)" = "$(cat "$s/api-jwt/public.pem")" ] || result=bad
	check "the JWT keys are a pair" $result
}

test_postgres_owns_its_key_and_only_it_can_read_it() {
	: >"$work/out"
	: >"$STUB_CHOWN_LOG"
	s="$work/owner"
	result=ok
	generate "$s" || result=bad
	for f in db/server.key pgbouncer/server.key pgbouncer/userlist.txt; do
		grep -qx "70:70 $s/$f" "$STUB_CHOWN_LOG" || result=bad
		[ "$(stat -c %a "$s/$f")" = 600 ] || result=bad
	done
	[ "$(stat -c %a "$s/.store")" = 700 ] || result=bad
	check "Postgres and pgbouncer own their key, readable by them only, and the store is closed" $result
}

test_rabbitmq_owns_its_key_and_only_it_can_read_it() {
	: >"$work/out"
	: >"$STUB_CHOWN_LOG"
	s="$work/rabbit"
	result=ok
	generate "$s" || result=bad
	grep -qx "100:101 $s/rabbitmq/server.key" "$STUB_CHOWN_LOG" || result=bad
	[ "$(stat -c %a "$s/rabbitmq/server.key")" = 600 ] || result=bad
	check "RabbitMQ owns its key, readable by it only" $result
}

test_a_failed_generation_leaves_no_partial_secret() {
	: >"$work/out"
	s="$work/broken"
	mkdir -p "$work/bin"
	cat >"$work/bin/openssl" <<'EOF'
#!/bin/sh
[ "$1" = ecparam ] && { echo half >"$7"; exit 1; }
exec /usr/bin/openssl "$@"
EOF
	chmod +x "$work/bin/openssl"
	result=ok
	PATH="$work/bin:$PATH" generate "$s" && result=bad
	[ -z "$(find "$s/.store" -name "*jwt_private*")" ] || result=bad
	generate "$s" || result=bad
	[ "$(openssl ec -in "$s/api-jwt/private.pem" -pubout 2>/dev/null)" = "$(cat "$s/api-jwt/public.pem")" ] || result=bad
	check "a failed generation fails the job, leaves no partial secret, and the next run completes" $result
}

test_an_empty_volume_gets_every_secret_each_service_reads
test_a_second_run_changes_nothing
test_an_existing_secret_is_kept_and_missing_ones_are_added
test_each_role_gets_its_own_password_and_services_agree_on_it
test_two_instances_share_no_secret
test_the_certificates_verify_for_the_names_clients_use
test_the_jwt_keys_are_a_pair
test_postgres_owns_its_key_and_only_it_can_read_it
test_rabbitmq_owns_its_key_and_only_it_can_read_it
test_a_failed_generation_leaves_no_partial_secret

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
