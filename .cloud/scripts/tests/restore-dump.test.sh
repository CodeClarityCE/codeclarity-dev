#!/bin/sh
# Tests that dump sets made by dump-knowledge-in-db.sh restore, and that damaged ones are refused
# before anything is restored. Uses stand-in pg_dump, psql, pg_restore, createdb, docker and git.
# Usage: sh .cloud/scripts/tests/restore-dump.test.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
DEPLOYMENT_DIR=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
export DEPLOYMENT_DIR
dump_script="$here/../dump-knowledge-in-db.sh"
restore_script="$DEPLOYMENT_DIR/scripts/restore-dump.sh"
[ -f "$restore_script" ] || { echo "no $restore_script; set DEPLOYMENT_DIR to a deployment checkout" >&2; exit 1; }
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_RESTORE_LOG="$work/restored"
export STUB_RESTORE_LOG

pass_report='{"passed": true, "checks": [{"name": "nvd.rows", "expected": "> 0", "actual": 402754, "pass": true}]}'

# Whole-file sha256 of the stub's 2500-byte and 100-byte dumps (see dump-knowledge-in-db.test.sh).
sha_2500=cddc81c0741412111944f1ebfce6d068846260cd4fc356e6edad93be29503968
sha_100=c5f02cf031cac250c7e132b6a62bf6e3d5cbac13771a194b00470bb489b7058f

# dump_set makes a dump set with the real dump script: a 2500-byte knowledge and a 100-byte config.
dump_set() {
	dir="$work/$1"
	mkdir -p "$dir"
	printf '%s\n' "$pass_report" | DUMP_DIR="$dir" STUB_DUMP_BYTES_knowledge=2500 \
		sh "$dump_script" >"$work/out" 2>&1 || echo "dump_set: dump script failed" >>"$work/out"
	: >"$STUB_RESTORE_LOG"
}

# old_set makes the layout from before manifests: whole dumps only.
old_set() {
	dir="$work/$1"
	mkdir -p "$dir"
	for db in codeclarity knowledge config; do
		echo "old $db" >"$dir/$db.dump"
	done
	: >"$STUB_RESTORE_LOG"
}

verify() {
	DUMP_DIR="$1" sh "$restore_script" verify >>"$work/out" 2>&1
}

restore() {
	dir=$1
	shift
	DUMP_DIR="$dir" sh "$restore_script" restore "$@" >>"$work/out" 2>&1
}

# corrupt flips the first byte of a file.
corrupt() {
	{ printf 'X'; tail -c +2 "$1"; } >"$1.tmp" && mv "$1.tmp" "$1"
}

listing() {
	# shellcheck disable=SC2012 # test dirs hold only plain file names
	(cd "$1" && ls -A | LC_ALL=C sort)
}

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$work/out"
		sed 's/^/     restored: /' "$STUB_RESTORE_LOG"
	fi
	: >"$work/out"
}

test_a_dump_set_verifies_and_restores() {
	dump_set whole
	before=$(listing "$dir")
	result=ok
	verify "$dir" || result=bad
	restore "$dir" knowledge knowledge || result=bad
	restore "$dir" config config_test || result=bad
	[ "$(cat "$STUB_RESTORE_LOG")" = "$(printf '%s\n' "knowledge $sha_2500" "config_test $sha_100")" ] || result=bad
	[ "$(listing "$dir")" = "$before" ] || result=bad
	check "a dump set from the dump script verifies and restores" $result
}

test_a_corrupted_dump_is_refused() {
	dump_set bad_file
	corrupt "$dir/knowledge.dump"
	result=ok
	verify "$dir" && result=bad
	grep -q "knowledge.dump" "$work/out" || result=bad
	restore "$dir" knowledge knowledge && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "a corrupted dump is refused by verify and by restore" $result
}

test_a_missing_dump_is_refused() {
	dump_set missing_dump
	rm "$dir/knowledge.dump"
	result=ok
	verify "$dir" && result=bad
	restore "$dir" knowledge knowledge && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "a missing dump is refused" $result
}

test_a_split_dump_part_is_refused() {
	dump_set extra_part
	echo stray >"$dir/knowledge.dump.part-aaa"
	result=ok
	verify "$dir" && result=bad
	grep -q "knowledge.dump.part-aaa" "$work/out" || result=bad
	restore "$dir" knowledge knowledge && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "a split dump part is refused: dumps ship whole" $result
}

test_a_dump_matching_an_edited_checksum_list_is_refused() {
	dump_set edited_sums
	corrupt "$dir/knowledge.dump"
	new=$(sha256sum "$dir/knowledge.dump" | cut -d' ' -f1)
	sed "s/^[0-9a-f]*  knowledge.dump\$/$new  knowledge.dump/" "$dir/knowledge-manifest.sha256" >"$work/sums"
	cp "$work/sums" "$dir/knowledge-manifest.sha256"
	result=ok
	verify "$dir" && result=bad
	restore "$dir" knowledge knowledge && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "a dump must match the manifest's SHA-256, not only the checksum list" $result
}

test_an_unknown_manifest_format_is_refused() {
	dump_set format_2
	sed 's/"format": 1,/"format": 2,/' "$dir/knowledge-manifest.json" >"$work/m" && cp "$work/m" "$dir/knowledge-manifest.json"
	result=ok
	verify "$dir" && result=bad
	grep -q "format" "$work/out" || result=bad
	restore "$dir" config config && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "a manifest format other than 1 is refused" $result
}

test_a_manifest_without_its_checksum_list_is_refused() {
	dump_set no_sums
	rm "$dir/knowledge-manifest.sha256"
	result=ok
	verify "$dir" && result=bad
	restore "$dir" config config && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "a manifest without knowledge-manifest.sha256 is refused" $result
}

test_the_old_layout_still_restores_with_a_warning() {
	old_set old
	result=ok
	verify "$dir" || result=bad
	grep -q "not verified" "$work/out" || result=bad
	restore "$dir" knowledge knowledge || result=bad
	[ "$(cat "$STUB_RESTORE_LOG")" = "knowledge $(sha256sum "$dir/knowledge.dump" | cut -d' ' -f1)" ] || result=bad
	check "an old dump set without a manifest restores, with a warning" $result
}

test_parts_without_a_manifest_are_refused() {
	old_set parts_no_manifest
	echo part >"$dir/knowledge.dump.part-aaa"
	result=ok
	verify "$dir" && result=bad
	restore "$dir" knowledge knowledge && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "split parts without a manifest are refused" $result
}

test_a_failed_pg_restore_fails_the_restore() {
	dump_set restore_fails
	result=ok
	STUB_PG_RESTORE_FAIL=knowledge restore "$dir" knowledge knowledge && result=bad
	grep -q "stub failure" "$work/out" || result=bad
	# shellcheck disable=SC2010 # test dirs hold only plain file names
	[ -z "$(cd "$dir" && ls -A | grep '^\.restore')" ] || result=bad
	check "a pg_restore error fails the restore and cleans up" $result
}

test_a_missing_database_is_created() {
	dump_set missing_db
	result=ok
	STUB_MISSING_DB=knowledge_test restore "$dir" knowledge knowledge_test || result=bad
	[ "$(head -1 "$STUB_RESTORE_LOG")" = "createdb knowledge_test" ] || result=bad
	check "a missing target database is created first" $result
}

test_a_dump_outside_the_manifest_restores_unverified() {
	dump_set codeclarity
	echo codeclarity >"$dir/codeclarity.dump"
	result=ok
	verify "$dir" || result=bad
	restore "$dir" codeclarity codeclarity || result=bad
	[ "$(cat "$STUB_RESTORE_LOG")" = "codeclarity $(sha256sum "$dir/codeclarity.dump" | cut -d' ' -f1)" ] || result=bad
	check "codeclarity.dump, which the manifest does not cover, still restores" $result
}

# fake_deployment copies the deployment scripts next to a dump set, with a stand-in git.
fake_deployment() {
	dump_set "$1/dump"
	cp -R "$DEPLOYMENT_DIR/scripts" "$work/$1/scripts"
	dir="$work/$1"
}

test_download_dumps_verifies_the_set() {
	fake_deployment download_ok
	result=ok
	STUB_GIT_LOG="$work/git-calls" sh "$dir/scripts/download-dumps.sh" >>"$work/out" 2>&1 || result=bad
	[ -f "$work/git-calls" ] && result=bad
	fake_deployment download_bad
	corrupt "$dir/dump/knowledge.dump"
	sh "$dir/scripts/download-dumps.sh" >>"$work/out" 2>&1 && result=bad
	check "download-dumps passes a good set and fails on a corrupted dump" $result
}

test_download_dumps_pulls_lfs_pointers() {
	fake_deployment download_pointer
	printf 'version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1000\n' >"$dir/dump/knowledge.dump"
	result=ok
	STUB_GIT_LOG="$work/git-calls" sh "$dir/scripts/download-dumps.sh" >>"$work/out" 2>&1 && result=bad
	grep -q "lfs pull" "$work/git-calls" || result=bad
	rm -f "$work/git-calls"
	check "download-dumps pulls LFS pointer files, then still refuses what does not verify" $result
}

# restore_database runs make restore-database with the stand-in docker on a dump directory.
restore_database() {
	DUMP_DIR="$1" make --no-print-directory -C "$root" restore-database >>"$work/out" 2>&1
}

test_restore_database_restores_every_database() {
	dump_set make_ok
	echo codeclarity >"$dir/codeclarity.dump"
	result=ok
	restore_database "$dir" || result=bad
	[ "$(cut -d' ' -f1 "$STUB_RESTORE_LOG" | tr '\n' ' ')" = "codeclarity knowledge config knowledge_test config_test codeclarity_test " ] || result=bad
	grep -q "^knowledge $sha_2500\$" "$STUB_RESTORE_LOG" || result=bad
	check "make restore-database verifies, then restores every database" $result
}

test_restore_database_restores_nothing_from_a_corrupted_set() {
	dump_set make_bad
	echo codeclarity >"$dir/codeclarity.dump"
	corrupt "$dir/knowledge.dump"
	result=ok
	restore_database "$dir" && result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "make restore-database restores nothing, not even codeclarity, from a corrupted set" $result
}

# restore_if_empty runs the setup job's command on a dump directory.
restore_if_empty() {
	DUMP_DIR="$1" sh "$restore_script" restore-if-empty >>"$work/out" 2>&1
}

test_an_empty_knowledge_database_gets_the_dump() {
	dump_set empty_knowledge
	result=ok
	STUB_RESTORE_ARGS_LOG="$work/args" restore_if_empty "$dir" || result=bad
	[ "$(cat "$STUB_RESTORE_LOG")" = "$(printf '%s\n' "config $sha_100" "knowledge $sha_2500")" ] || result=bad
	grep -q -- "--role=cc_knowledge .*-d knowledge" "$work/args" || result=bad
	grep -q -- "--role=cc_api .*-d config" "$work/args" || result=bad
	check "restore-if-empty restores knowledge and config, owned by their roles, into an empty knowledge database" $result
}

test_a_knowledge_database_with_tables_is_left_alone() {
	dump_set has_knowledge
	corrupt "$dir/config.dump"
	result=ok
	STUB_TABLES_knowledge=40 restore_if_empty "$dir" || result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	grep -q "nothing to restore" "$work/out" || result=bad
	check "restore-if-empty restores nothing, and reads no dump, when knowledge already has tables" $result
}

test_restore_if_empty_stops_on_a_dump_failing_its_manifest() {
	dump_set empty_bad
	corrupt "$dir/knowledge.dump"
	result=ok
	restore_if_empty "$dir" && result=bad
	grep -q "does not match its manifest" "$work/out" || result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "restore-if-empty fails with a clear error and restores nothing from a set failing its manifest" $result
}

test_restore_if_empty_needs_a_manifest() {
	old_set empty_old
	result=ok
	restore_if_empty "$dir" && result=bad
	grep -q "no knowledge-manifest.json" "$work/out" || result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "restore-if-empty refuses a dump set without a manifest" $result
}

test_restore_if_empty_keeps_a_config_database_with_tables() {
	dump_set has_config
	result=ok
	STUB_TABLES_config=1 restore_if_empty "$dir" || result=bad
	[ "$(cat "$STUB_RESTORE_LOG")" = "knowledge $sha_2500" ] || result=bad
	check "restore-if-empty restores knowledge but keeps a config database that has tables" $result
}

test_restore_if_empty_fails_when_knowledge_cannot_be_read() {
	dump_set unreadable
	result=ok
	STUB_TABLES_knowledge=error restore_if_empty "$dir" && result=bad
	grep -q "cannot read the knowledge database" "$work/out" || result=bad
	[ -s "$STUB_RESTORE_LOG" ] && result=bad
	check "restore-if-empty fails, restoring nothing, when it cannot read the knowledge database" $result
}

test_a_dump_set_verifies_and_restores
test_a_corrupted_dump_is_refused
test_a_missing_dump_is_refused
test_a_split_dump_part_is_refused
test_a_dump_matching_an_edited_checksum_list_is_refused
test_an_unknown_manifest_format_is_refused
test_a_manifest_without_its_checksum_list_is_refused
test_the_old_layout_still_restores_with_a_warning
test_parts_without_a_manifest_are_refused
test_a_failed_pg_restore_fails_the_restore
test_a_missing_database_is_created
test_a_dump_outside_the_manifest_restores_unverified
test_download_dumps_verifies_the_set
test_download_dumps_pulls_lfs_pointers
test_restore_database_restores_every_database
test_restore_database_restores_nothing_from_a_corrupted_set
test_an_empty_knowledge_database_gets_the_dump
test_a_knowledge_database_with_tables_is_left_alone
test_restore_if_empty_stops_on_a_dump_failing_its_manifest
test_restore_if_empty_needs_a_manifest
test_restore_if_empty_keeps_a_config_database_with_tables
test_restore_if_empty_fails_when_knowledge_cannot_be_read

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
