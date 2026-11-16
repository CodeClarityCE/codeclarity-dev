#!/bin/sh
# Tests the knowledge dump tag pruning: dated tags from the 8 weeks up to the newest, every tag
# a deployment release pins and the tag the dev Compose file on main pins stay, every other
# dated tag is deleted, and nothing is deleted when the pins cannot be read. Uses stand-ins for gh (releases) and curl (Docker Hub).
# Usage: sh .cloud/scripts/tests/prune-knowledge-dump-tags.test.sh
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../prune-knowledge-dump-tags.sh"
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_RELEASES="$work/releases.json"
STUB_ASSETS="$work/assets"
STUB_HUB_DELETED="$work/deleted"
STUB_CURL_LOG="$work/curl.log"
STUB_CONTENTS="$work/dev-compose.yaml"
DOCKERHUB_USERNAME=ci DOCKERHUB_TOKEN=secret
export STUB_CONTENTS STUB_RELEASES STUB_ASSETS STUB_HUB_DELETED STUB_CURL_LOG DOCKERHUB_USERNAME DOCKERHUB_TOKEN

# Twelve weekly builds, oldest first.
WEEKLY="2026-08-29 2026-09-05 2026-09-12 2026-09-19 2026-09-26 2026-10-03 2026-10-10 2026-10-17 2026-10-24 2026-10-31 2026-11-07 2026-11-14"

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

reset() {
	rm -rf "$STUB_ASSETS" "$STUB_HUB_DELETED" "$STUB_CURL_LOG"
	mkdir -p "$STUB_ASSETS"
	: >"$STUB_HUB_DELETED"
	dev_compose_pinning 2026-11-14
	unset STUB_GH_FAIL STUB_HUB_AUTH_FAIL STUB_HUB_LIST_FAIL STUB_HUB_DELETE_FAIL
}

# Deployment releases, newest first, each pinning the knowledge dump tag given; "-" is an
# old release with no Compose file attached.
releases_pinning() {
	id=0 json=""
	for tag; do
		id=$((id + 1))
		if [ "$tag" = - ]; then
			json="$json{\"tag_name\":\"v0.0.$id-alpha\",\"assets\":[]},"
			continue
		fi
		json="$json{\"tag_name\":\"v0.0.$id-alpha\",\"assets\":[{\"id\":$id,\"name\":\"env.example\"},{\"id\":$((id + 100)),\"name\":\"docker-compose.yaml\"}]},"
		# shellcheck disable=SC2016 # the Compose variable is written as it is
		printf '  knowledge-restore:\n    image: ${KNOWLEDGE_DUMP_IMAGE:-codeclarityce/knowledge-dump:%s@sha256:%064d}\n' \
			"$tag" 0 >"$STUB_ASSETS/$((id + 100))"
	done
	printf '[%s]\n' "${json%,}" >"$STUB_RELEASES"
}

# The dev Compose file on main, pinning the knowledge dump tag given.
dev_compose_pinning() {
	# shellcheck disable=SC2016 # the Compose variable is written as it is
	printf '  knowledge-restore:\n    image: ${KNOWLEDGE_DUMP_IMAGE:-codeclarityce/knowledge-dump:%s}\n' "$1" >"$STUB_CONTENTS"
}

prune() {
	sh "$script" >"$work/out" 2>&1
}

# The deleted tags, sorted, on one line.
deleted() {
	sort "$STUB_HUB_DELETED" | paste -s -d' ' -
}

test_only_old_unpinned_dated_tags_are_deleted() {
	reset
	releases_pinning 2026-09-05 -
	export STUB_HUB_TAGS="latest $WEEKLY"
	result=ok
	prune || result=bad
	[ "$(deleted)" = "2026-08-29 2026-09-12 2026-09-19" ] || result=bad
	check "dated tags older than 8 weeks before the newest are deleted, except one a release pins and non-date tags" $result
}

test_every_tag_any_release_pins_is_kept() {
	reset
	releases_pinning 2026-11-07 2026-09-19 - 2026-08-29
	export STUB_HUB_TAGS="$WEEKLY"
	result=ok
	prune || result=bad
	[ "$(deleted)" = "2026-09-05 2026-09-12" ] || result=bad
	check "a tag pinned by an older release is kept as well as one pinned by the newest" $result
}

test_manual_builds_do_not_push_weekly_tags_out() {
	reset
	releases_pinning
	export STUB_HUB_TAGS="$WEEKLY 2026-11-10 2026-11-11 2026-11-12 2026-10-29"
	result=ok
	prune || result=bad
	[ "$(deleted)" = "2026-08-29 2026-09-05 2026-09-12 2026-09-19" ] || result=bad
	check "extra manual builds keep every weekly tag of the last 8 weeks" $result
}

test_the_tag_the_dev_compose_file_pins_is_kept() {
	reset
	releases_pinning
	dev_compose_pinning 2026-09-12
	export STUB_HUB_TAGS="$WEEKLY"
	result=ok
	prune || result=bad
	[ "$(deleted)" = "2026-08-29 2026-09-05 2026-09-19" ] || result=bad
	check "the tag the dev Compose file on main pins is kept" $result
}

test_nothing_is_deleted_when_the_dev_compose_file_cannot_be_read() {
	reset
	releases_pinning
	rm "$STUB_CONTENTS"
	export STUB_HUB_TAGS="$WEEKLY"
	result=ok
	prune && result=bad
	[ -s "$STUB_HUB_DELETED" ] && result=bad
	grep -q DELETE "$STUB_CURL_LOG" 2>/dev/null && result=bad
	grep -q 'deleting nothing' "$work/out" || result=bad
	check "nothing is deleted, and the run fails, when the dev Compose file on main cannot be read" $result
}

test_nothing_is_deleted_with_eight_tags_or_fewer() {
	reset
	releases_pinning
	export STUB_HUB_TAGS="2026-10-03 2026-10-10 2026-10-17 2026-10-24 2026-10-31 2026-11-07 2026-11-14 2026-09-26"
	result=ok
	prune || result=bad
	[ -s "$STUB_HUB_DELETED" ] && result=bad
	check "nothing is deleted while every dated tag is within 8 weeks of the newest" $result
}

test_nothing_is_deleted_when_the_releases_cannot_be_listed() {
	reset
	releases_pinning 2026-09-05
	export STUB_HUB_TAGS="$WEEKLY" STUB_GH_FAIL=1
	result=ok
	prune && result=bad
	[ -s "$STUB_HUB_DELETED" ] && result=bad
	grep -q DELETE "$STUB_CURL_LOG" 2>/dev/null && result=bad
	grep -q 'deleting nothing' "$work/out" || result=bad
	check "nothing is deleted, and the run fails, when the releases cannot be listed" $result
}

test_nothing_is_deleted_when_a_release_compose_file_cannot_be_read() {
	reset
	releases_pinning 2026-11-07 2026-09-05
	rm "$STUB_ASSETS/102"
	export STUB_HUB_TAGS="$WEEKLY"
	result=ok
	prune && result=bad
	[ -s "$STUB_HUB_DELETED" ] && result=bad
	grep -q DELETE "$STUB_CURL_LOG" 2>/dev/null && result=bad
	check "nothing is deleted, and the run fails, when one release's Compose file cannot be downloaded" $result
}

test_nothing_is_deleted_when_the_tags_cannot_be_listed() {
	reset
	releases_pinning
	export STUB_HUB_TAGS="$WEEKLY" STUB_HUB_LIST_FAIL=1
	result=ok
	prune && result=bad
	[ -s "$STUB_HUB_DELETED" ] && result=bad
	check "nothing is deleted, and the run fails, when Docker Hub cannot list the tags" $result
}

test_a_failed_delete_fails_the_run_after_the_others() {
	reset
	releases_pinning
	export STUB_HUB_TAGS="$WEEKLY" STUB_HUB_DELETE_FAIL=2026-09-05
	result=ok
	prune && result=bad
	[ "$(deleted)" = "2026-08-29 2026-09-12 2026-09-19" ] || result=bad
	grep -q 'cannot delete codeclarityce/knowledge-dump:2026-09-05' "$work/out" || result=bad
	check "a tag Docker Hub refuses to delete fails the run, and the other old tags are still deleted" $result
}

test_only_old_unpinned_dated_tags_are_deleted
test_every_tag_any_release_pins_is_kept
test_manual_builds_do_not_push_weekly_tags_out
test_the_tag_the_dev_compose_file_pins_is_kept
test_nothing_is_deleted_when_the_dev_compose_file_cannot_be_read
test_nothing_is_deleted_with_eight_tags_or_fewer
test_nothing_is_deleted_when_the_releases_cannot_be_listed
test_nothing_is_deleted_when_a_release_compose_file_cannot_be_read
test_nothing_is_deleted_when_the_tags_cannot_be_listed
test_a_failed_delete_fails_the_run_after_the_others

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
