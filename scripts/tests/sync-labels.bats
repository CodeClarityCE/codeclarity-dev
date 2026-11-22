#!/usr/bin/env bats
# Tests sync-labels.sh: check mode reports labels that are missing or differ, apply mode
# creates or edits only those, and other labels are left alone. gh is the stand-in in stubs/.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
	mkdir -p "$BATS_TEST_TMPDIR/labels"
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	case "$1 $2" in
	"repo list") printf '%s\n' api frontend ;;
	"label list")
		local repo="${4#CodeClarityCE/}" file
		file="$BATS_TEST_TMPDIR/labels/$repo.json"
		[[ -f "$file" ]] && cat "$file" || echo '[]'
		;;
	"label create") return 0 ;;
	*) echo "unexpected: $*" >&2; return 1 ;;
	esac
}
RULES
	export BATS_TEST_TMPDIR
}

# Gives <repo> every managed label exactly as sync-labels.sh defines it.
complete_labels() {
	sourced sync-labels.sh managed_labels_json >"$BATS_TEST_TMPDIR/labels/$1.json"
}

@test "check mode names a missing label and fails" {
	run "$ROOT_DIR/scripts/sync-labels.sh" --check api
	[ "$status" -eq 1 ]
	[[ "$output" == *"api: missing P1"* ]]
}

@test "check mode passes when every managed label matches, whatever the case of names and colors" {
	sourced sync-labels.sh managed_labels_json |
		jq '(.[] | select(.name == "P1")) |= (.name = "p1" | .color = (.color | ascii_downcase))' >"$BATS_TEST_TMPDIR/labels/api.json"
	run "$ROOT_DIR/scripts/sync-labels.sh" --check api
	[ "$status" -eq 0 ]
	[ "$output" = "labels in sync" ]
}

@test "check mode reports a label whose color or description differs" {
	sourced sync-labels.sh managed_labels_json |
		jq '(.[] | select(.name == "P2")).color = "000000" | (.[] | select(.name == "wontfix")).description = ""' \
			>"$BATS_TEST_TMPDIR/labels/api.json"
	run "$ROOT_DIR/scripts/sync-labels.sh" --check api
	[ "$status" -eq 1 ]
	[ "$output" = $'api: differs P2\napi: differs wontfix' ]
}

@test "check mode writes nothing" {
	run "$ROOT_DIR/scripts/sync-labels.sh" --check api
	! grep -q "label create" "$GH_STUB_LOG"
}

@test "apply creates missing labels, edits differing ones and leaves the rest alone" {
	sourced sync-labels.sh managed_labels_json |
		jq 'map(select(.name != "P3")) | (.[] | select(.name == "P1")).description = "old" | . + [{name: "bug", color: "d73a4a", description: "x"}]' \
			>"$BATS_TEST_TMPDIR/labels/api.json"
	run "$ROOT_DIR/scripts/sync-labels.sh" api
	[ "$status" -eq 0 ]
	[ "$output" = $'api: updated P1\napi: created P3' ]
	[ "$(grep -c 'label create' "$GH_STUB_LOG")" -eq 2 ]
	grep -q -- "label create P1 -R CodeClarityCE/api --force --color B60205 --description Urgent: crash, data loss, security hole or wrong results" "$GH_STUB_LOG"
	grep -q -- "label create P3 -R CodeClarityCE/api --force --color FBCA04" "$GH_STUB_LOG"
	! grep -q "bug" "$GH_STUB_LOG"
}

@test "with no repo names it covers every non-archived repo in the org" {
	complete_labels api
	run "$ROOT_DIR/scripts/sync-labels.sh" --check
	[ "$status" -eq 1 ]
	grep -q -- "repo list CodeClarityCE --no-archived" "$GH_STUB_LOG"
	[[ "$output" != *"api:"* ]]
	[[ "$output" == *"frontend: missing P1"* ]]
}

@test "a repo whose labels cannot be read stops the run" {
	cat >>"$GH_STUB_RULES" <<'RULES'
gh_stub() { echo "HTTP 404: Not Found" >&2; return 1; }
RULES
	run "$ROOT_DIR/scripts/sync-labels.sh" --check api
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not read the labels of CodeClarityCE/api"* ]]
}

@test "the managed set holds the severity and triage labels, with P1 covering wrong results" {
	run sourced sync-labels.sh managed_labels_json
	[ "$(jq -r '[.[].name] | join(",")' <<<"$output")" = "P1,P2,P3,good first issue,help wanted,needs-triage,needs-info,ready-for-agent,ready-for-human,wontfix" ]
	jq -e '.[] | select(.name == "P1") | .description | test("wrong results")' <<<"$output"
	jq -e 'all(.[]; (.description | length) <= 100)' <<<"$output"
}

@test "an unknown option is refused" {
	run "$ROOT_DIR/scripts/sync-labels.sh" --apply
	[ "$status" -eq 1 ]
	[[ "$output" == *"unknown option --apply"* ]]
}
