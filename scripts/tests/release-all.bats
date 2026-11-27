#!/usr/bin/env bats
# Tests release-all.sh: version comparison, next-tag choice, releaser choice, the Go build that
# writes no binary, version file, the root lockfile regenerated with a moved api or frontend
# pointer, and that a releasing caller with CI_RELEASE off stops the whole run before any PR.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
	# A docker on PATH for preflight; any real call fails, since only root-lockfile.sh uses it.
	mkdir -p "$BATS_TEST_TMPDIR/bin"
	cat >"$BATS_TEST_TMPDIR/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
echo "docker stub: unexpected call: $*" >&2
exit 1
DOCKER
	chmod +x "$BATS_TEST_TMPDIR/bin/docker"
	PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

# Runs one release-all.sh function after parsing the given flags, e.g. rel_with "--suffix beta" bump.
rel_with() {
	bash -c 's=$1 flags=$2; shift 2; args=("$@"); set --; source "$s"; read -ra f <<<"$flags"; parse_args "${f[@]}"; "${args[@]}"' \
		_ "$ROOT_DIR/scripts/release-all.sh" "$@"
}

# --- version comparison -------------------------------------------------------------------

@test "version_gt compares patch numbers numerically" {
	run rel version_gt v0.0.10-alpha v0.0.9-alpha
	[ "$status" -eq 0 ]
	run rel version_gt v0.0.9-alpha v0.0.10-alpha
	[ "$status" -ne 0 ]
}

@test "version_gt puts beta after alpha of the same version" {
	run rel version_gt v0.1.0-beta v0.1.0-alpha
	[ "$status" -eq 0 ]
	run rel version_gt v0.1.0-alpha v0.1.0-beta
	[ "$status" -ne 0 ]
}

@test "version_gt puts a higher alpha after a lower release" {
	run rel version_gt v0.2.0-alpha v0.1.9
	[ "$status" -eq 0 ]
}

@test "version_gt is false for equal versions" {
	run rel version_gt v1.2.3-alpha v1.2.3-alpha
	[ "$status" -ne 0 ]
}

@test "bump raises the patch number and keeps the suffix" {
	run rel bump v0.0.9-alpha
	[ "$output" = v0.0.10-alpha ]
	run rel bump v1.2.3
	[ "$output" = v1.2.4 ]
}

@test "bump with a new suffix raises the patch number and swaps the suffix" {
	run rel bump v0.0.9-alpha beta
	[ "$status" -eq 0 ]
	[ "$output" = v0.0.10-beta ]
	run rel bump v0.0.10-beta beta
	[ "$output" = v0.0.11-beta ]
}

@test "bump refuses a version it cannot parse" {
	run rel bump 1.2
	[ "$status" -ne 0 ]
	[[ "$output" == *"cannot bump version '1.2'"* ]]
}

# --- next tag -----------------------------------------------------------------------------

# A Go repo whose main is tagged v0.1.0-alpha, with that version in config.json.
released_go_repo() {
	init_repo backend/utilities/types
	commit_file backend/utilities/types config.json '{ "version": "v0.1.0-alpha" }'
	merge_to_main backend/utilities/types
	tag_main backend/utilities/types v0.1.0-alpha
}

@test "latest_tag survives a tag list longer than one pipe write, under pipefail" {
	released_go_repo
	# Enough tags that git is still writing when a reader of the first line exits.
	local main i
	main="$(git -C "$ROOT_DIR/backend/utilities/types" rev-parse origin/main)"
	for i in $(seq 1 600); do echo "create refs/tags/v0.0.$i-alpha $main"; done |
		git -C "$ROOT_DIR/backend/utilities/types" update-ref --stdin
	run rel latest_tag backend/utilities/types
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.0-alpha ]
}

@test "next_tag bumps the latest tag when main holds no newer version" {
	released_go_repo
	commit_file backend/utilities/types main.go 'package types'
	run rel next_tag backend/utilities/types v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.1-alpha ]
}

@test "next_tag reuses main's untagged version when develop is at main" {
	released_go_repo
	commit_file backend/utilities/types config.json '{ "version": "v0.1.1-alpha" }'
	merge_to_main backend/utilities/types
	run rel next_tag backend/utilities/types v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.1-alpha ]
}

@test "next_tag bumps past main's untagged version when develop has new commits" {
	released_go_repo
	commit_file backend/utilities/types config.json '{ "version": "v0.1.1-alpha" }'
	merge_to_main backend/utilities/types
	commit_file backend/utilities/types main.go 'package types'
	run rel next_tag backend/utilities/types v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.2-alpha ]
}

@test "next_tag reads main's package.json version, which has no v" {
	init_repo api
	caller api node-image.yml
	commit_file api package.json '{ "name": "api", "version": "0.1.1-alpha" }'
	merge_to_main api
	run rel next_tag api v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.1-alpha ]
}

@test "next_tag with a new suffix bumps the latest tag to that suffix" {
	released_go_repo
	commit_file backend/utilities/types main.go 'package types'
	run rel_with "--suffix beta" next_tag backend/utilities/types v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.1-beta ]
}

@test "next_tag with a new suffix reuses main's untagged version of that suffix" {
	released_go_repo
	commit_file backend/utilities/types config.json '{ "version": "v0.1.1-beta" }'
	merge_to_main backend/utilities/types
	run rel_with "--suffix beta" next_tag backend/utilities/types v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.1-beta ]
}

@test "next_tag with a new suffix bumps past main's untagged version of the old suffix" {
	released_go_repo
	commit_file backend/utilities/types config.json '{ "version": "v0.1.1-alpha" }'
	merge_to_main backend/utilities/types
	run rel_with "--suffix beta" next_tag backend/utilities/types v0.1.0-alpha
	[ "$status" -eq 0 ]
	[ "$output" = v0.1.2-beta ]
}

@test "--suffix refuses anything but lowercase letters" {
	run rel_with "--suffix -beta" true
	[ "$status" -eq 2 ]
	[[ "$output" == *"--suffix takes lowercase letters only"* ]]
}

# --- releaser -----------------------------------------------------------------------------

@test "releaser is the script for a repo without a caller" {
	run rel releaser api
	[ "$status" -eq 0 ]
	[ "$output" = script ]
}

@test "releaser is the script for a caller without release jobs" {
	caller . workflow-lint.yml
	run rel releaser .
	[ "$status" -eq 0 ]
	[ "$output" = script ]
}

@test "releaser is Actions for a releasing caller with CI_RELEASE true" {
	local workflow
	for workflow in go-library.yml go-image.yml node-image.yml; do
		caller api "$workflow"
		set_variable api CI_RELEASE true
		run rel releaser api
		[ "$status" -eq 0 ]
		[ "$output" = actions ]
	done
}

@test "releaser is Actions for a caller with its own release job and CI_RELEASE true" {
	write_file deployment .github/workflows/ci.yml "jobs:
  release:
    if: github.ref == 'refs/heads/main' && vars.CI_RELEASE == 'true'"
	set_variable deployment CI_RELEASE true
	run rel releaser deployment
	[ "$status" -eq 0 ]
	[ "$output" = actions ]
}

@test "releaser stops on a releasing caller with CI_RELEASE false" {
	caller frontend node-image.yml
	set_variable frontend CI_RELEASE false
	run rel releaser frontend
	[ "$status" -ne 0 ]
	[[ "$output" == *"frontend has a releasing caller but CI_RELEASE is not true"* ]]
}

@test "releaser stops on a releasing caller with CI_RELEASE unset" {
	caller backend go-image.yml
	run rel releaser backend
	[ "$status" -ne 0 ]
	[[ "$output" == *"backend has a releasing caller but CI_RELEASE is not true"* ]]
}

@test "releaser is the release workflow for a repo with one and CI_RELEASE true" {
	write_file . .github/workflows/release.yml "on:
  workflow_dispatch:"
	caller . workflow-lint.yml
	set_variable . CI_RELEASE true
	run rel releaser .
	[ "$status" -eq 0 ]
	[ "$output" = workflow ]
}

@test "releaser ignores a release workflow that only runs on tag pushes" {
	write_file backend .github/workflows/release.yml "on:
  push:
    tags:
      - \"cli-v*\""
	run rel releaser backend
	[ "$status" -eq 0 ]
	[ "$output" = script ]
}

@test "releaser stops on a release workflow with CI_RELEASE unset" {
	write_file . .github/workflows/release.yml "on:
  workflow_dispatch:"
	caller . workflow-lint.yml
	run rel releaser .
	[ "$status" -ne 0 ]
	[[ "$output" == *". has a release workflow but CI_RELEASE is not true"* ]]
}

# --- release workflow ---------------------------------------------------------------------

# gh answers for the umbrella's release workflow: on dispatch it tags main (ok) or its run fails (fails).
release_workflow_rules() {
	cat >"$GH_STUB_RULES" <<RULES
gh_stub() {
	case "\$1 \$2" in
	"workflow run")
		[[ "$1" == ok ]] && git fetch -q origin && git tag "\${7#version=}" origin/main && git push -q origin "\${7#version=}"
		return 0
		;;
	"run list")
		echo '[{"displayTitle":"Release v0.1.0-alpha","status":"completed","conclusion":"failure","createdAt":"2000-01-01T00:00:00Z","url":"https://github.com/x/runs/1"},
		  {"displayTitle":"Release v0.1.1-alpha","status":"completed","conclusion":"$2","createdAt":"2999-01-01T00:00:00Z","url":"https://github.com/x/runs/2"}]'
		;;
	*) return 1 ;;
	esac
}
RULES
}

@test "publish_tag dispatches the release workflow on main with the tag and waits for the tag" {
	init_repo .
	write_file . .github/workflows/release.yml "on:
  workflow_dispatch:"
	merge_to_main .
	release_workflow_rules ok in_progress
	set_variable . CI_RELEASE true
	run rel publish_tag . v0.1.1-alpha
	[ "$status" -eq 0 ]
	grep -qx '.: workflow run release.yml --ref main -f version=v0.1.1-alpha' "$GH_STUB_LOG"
	[ -n "$(git -C "$ROOT_DIR" ls-remote --tags origin refs/tags/v0.1.1-alpha)" ]
}

@test "publish_tag stops with the run's link when the release workflow fails, as a failed SBOM does" {
	init_repo .
	write_file . .github/workflows/release.yml "on:
  workflow_dispatch:"
	release_workflow_rules fails failure
	set_variable . CI_RELEASE true
	run rel publish_tag . v0.1.1-alpha
	[ "$status" -ne 0 ]
	[[ "$output" == *"the Release workflow for v0.1.1-alpha ended with failure"*"https://github.com/x/runs/2"* ]]
	[ -z "$(git -C "$ROOT_DIR" ls-remote --tags origin refs/tags/v0.1.1-alpha)" ]
	run grep -q 'release create' "$GH_STUB_LOG"
	[ "$status" -eq 1 ]
}

# --- go build ---------------------------------------------------------------------------

# A stand-in go on PATH: logs each call; "go build" without -o writes a binary named after the
# directory, as for a main package; FAKE_GO_FAIL=build makes the build fail.
fake_go() {
	mkdir -p "$BATS_TEST_TMPDIR/bin"
	cat >"$BATS_TEST_TMPDIR/bin/go" <<'GO'
#!/usr/bin/env bash
echo "go $*" >>"$FAKE_GO_LOG"
if [[ "$1" == build ]]; then
	[[ "${FAKE_GO_FAIL:-}" == build ]] && exit 1
	[[ "$2" == -o ]] || : >"$(basename "$PWD")"
fi
exit 0
GO
	chmod +x "$BATS_TEST_TMPDIR/bin/go"
	export FAKE_GO_LOG="$BATS_TEST_TMPDIR/go.log"
	PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

# The Go repo with its go.mod committed, as in the fake tree.
go_repo() {
	init_repo backend/utilities/types
	git -C "$ROOT_DIR/backend/utilities/types" add go.mod
	git -C "$ROOT_DIR/backend/utilities/types" commit -q -m "Add go.mod"
}

@test "tidy_build compiles every package and leaves no binary in the repo" {
	fake_go
	go_repo
	run rel tidy_build backend/utilities/types
	[ "$status" -eq 0 ]
	grep -qx 'go mod tidy' "$FAKE_GO_LOG"
	grep -qx 'go build -o /dev/null ./...' "$FAKE_GO_LOG"
	[ -z "$(git -C "$ROOT_DIR/backend/utilities/types" status --porcelain)" ]
}

@test "tidy_build stops the release when the build fails" {
	fake_go
	go_repo
	FAKE_GO_FAIL=build run rel tidy_build backend/utilities/types
	[ "$status" -ne 0 ]
	[[ "$output" == *"backend/utilities/types: tidy/build failed"* ]]
}

# --- version file -------------------------------------------------------------------------

@test "version_file is config.json when the repo has one" {
	write_file backend/utilities/types config.json '{ "version": "v0.1.0-alpha" }'
	write_file backend/utilities/types package.json '{ "version": "0.0.1" }'
	run rel version_file backend/utilities/types
	[ "$output" = config.json ]
}

@test "version_file is package.json for a releasing Node caller" {
	caller frontend node-image.yml
	write_file frontend package.json '{ "version": "0.1.0-alpha" }'
	run rel version_file frontend
	[ "$output" = package.json ]
}

@test "version_file is none for a package.json without a releasing caller" {
	caller . workflow-lint.yml
	write_file . package.json '{ "private": true }'
	run rel version_file .
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# --- root lockfile ------------------------------------------------------------------------

# The umbrella with its four submodules and a tracked pnpm-lock.yaml, and a stand-in
# root-lockfile.sh that logs its mode and rewrites pnpm-lock.yaml (or fails with FAIL_LOCKFILE).
umbrella_with_lockfile() {
	local key
	for key in . backend api frontend deployment; do
		init_repo "$key"
	done
	write_file . pnpm-lock.yaml 'old'
	git -C "$ROOT_DIR" add pnpm-lock.yaml backend api frontend deployment
	git -C "$ROOT_DIR" commit -q -m "Track the submodules"
	export LOCKFILE_LOG="$BATS_TEST_TMPDIR/root-lockfile.log"
	cat >"$ROOT_DIR/scripts/root-lockfile.sh" <<'STUB'
echo "$*" >>"$LOCKFILE_LOG"
[[ -z "${FAIL_LOCKFILE:-}" ]] || exit 1
echo regenerated >"$(dirname "$0")/../pnpm-lock.yaml"
STUB
}

# The files the umbrella's last commit changed, space separated.
last_commit_files() {
	git -C "$ROOT_DIR" show --name-only --format= HEAD | sort | tr '\n' ' ' | sed 's/ $//'
}

@test "bump_submodules regenerates the root lockfile and commits it with a moved api pointer" {
	umbrella_with_lockfile
	commit_file api package.json '{ "name": "api" }'
	run rel bump_submodules .
	[ "$status" -eq 0 ]
	[ "$(cat "$LOCKFILE_LOG")" = update ]
	[ "$(git -C "$ROOT_DIR" log -1 --format=%s)" = "Update submodules" ]
	[ "$(last_commit_files)" = "api pnpm-lock.yaml" ]
}

@test "bump_submodules regenerates the root lockfile for a moved frontend pointer too" {
	umbrella_with_lockfile
	commit_file frontend package.json '{ "name": "frontend" }'
	run rel bump_submodules .
	[ "$status" -eq 0 ]
	[ "$(last_commit_files)" = "frontend pnpm-lock.yaml" ]
}

@test "bump_submodules leaves the root lockfile alone when only other pointers moved" {
	umbrella_with_lockfile
	commit_file deployment config.json '{ "version": "v0.1.0-alpha" }'
	run rel bump_submodules .
	[ "$status" -eq 0 ]
	[ ! -e "$LOCKFILE_LOG" ]
	[ "$(last_commit_files)" = deployment ]
}

@test "bump_submodules stops before committing when the root lockfile cannot be regenerated" {
	umbrella_with_lockfile
	commit_file api package.json '{ "name": "api" }'
	FAIL_LOCKFILE=1 run rel bump_submodules .
	[ "$status" -ne 0 ]
	[[ "$output" == *"could not regenerate the root pnpm-lock.yaml"* ]]
	[ "$(git -C "$ROOT_DIR" log -1 --format=%s)" = "Track the submodules" ]
}

# --- whole run ----------------------------------------------------------------------------

@test "a run without docker stops in preflight before any repo" {
	rm "$BATS_TEST_TMPDIR/bin/docker"
	PATH="$(tr ':' '\n' <<<"$PATH" | while read -r d; do [[ -x "$d/docker" ]] || printf '%s:' "$d"; done)"
	cd "$ROOT_DIR"
	run bash scripts/release-all.sh --yes
	[ "$status" -ne 0 ]
	[[ "$output" == *"docker is not installed"* ]]
	[ ! -s "$GH_STUB_LOG" ] || ! grep -q ' pr ' "$GH_STUB_LOG"
}

@test "a releasing caller with CI_RELEASE off stops the whole run before any PR" {
	local key
	for key in backend/utilities/types backend api frontend deployment .; do
		init_repo "$key"
		tag_main "$key" v0.1.0-alpha
	done
	# api has work to release, so only the CI_RELEASE stop keeps it from opening a PR.
	caller api node-image.yml
	commit_file api README.md 'api'
	set_variable api CI_RELEASE false

	cd "$ROOT_DIR"
	run bash scripts/release-all.sh --yes
	[ "$status" -eq 1 ]
	[[ "$output" == *"api has a releasing caller but CI_RELEASE is not true"* ]]
	# The repos before api were handled, nothing after it was, and no PR was touched.
	grep -qx 'backend/utilities/types=v0.1.0-alpha' scripts/.release-state
	grep -qx 'backend=v0.1.0-alpha' scripts/.release-state
	run grep -q ' pr ' "$GH_STUB_LOG"
	[ "$status" -eq 1 ]
	run grep -q '^frontend' "$GH_STUB_LOG"
	[ "$status" -eq 1 ]
}

# Every repo of the fake tree, tagged v0.1.0-alpha on main with nothing new on develop.
released_tree() {
	local key
	for key in backend/utilities/types backend api frontend deployment .; do
		init_repo "$key"
		tag_main "$key" v0.1.0-alpha
	done
}

@test "a dry run with a new suffix plans it for every repo, changed or not" {
	released_tree
	cd "$ROOT_DIR"
	run bash scripts/release-all.sh --dry-run --suffix beta
	[ "$status" -eq 0 ]
	local key
	for key in backend/utilities/types backend api frontend deployment .; do
		[[ "$output" == *$'\n'"$(printf '%-32s' "$key") v0.1.0-alpha    -> v0.1.1-beta "* ]]
	done
}

# gh answers for a release PR that merges at once and a release the script creates.
release_pr_rules() {
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	local merged="$GH_STUB_DIR/${repo//\//_}.merged"
	case "$1 $2" in
	"pr list") ;;
	"pr create") echo "https://github.com/CodeClarityCE/x/pull/7" ;;
	"pr merge") git push -q origin develop:main && touch "$merged" ;;
	"pr view") if [[ -f "$merged" ]]; then echo MERGED; else echo OPEN; fi ;;
	"release create") git fetch -q origin && git tag "$3" origin/main && git push -q origin "$3" ;;
	*) return 1 ;;
	esac
}
RULES
}

@test "a run with a new suffix releases every repo once, version files included" {
	released_tree
	commit_file backend/utilities/types config.json '{ "version": "v0.1.0-alpha" }'
	commit_file deployment config.json '{ "version": "v0.1.0-alpha" }'
	release_pr_rules

	cd "$ROOT_DIR"
	run bash scripts/release-all.sh --yes --suffix beta
	[ "$status" -eq 0 ]
	local key
	for key in backend/utilities/types backend api frontend deployment .; do
		grep -qx "$key=v0.1.1-beta" scripts/.release-state
		[ -n "$(git -C "$key" ls-remote --tags origin refs/tags/v0.1.1-beta)" ]
	done
	[ "$(git -C deployment show origin/main:config.json | jq -r .version)" = v0.1.1-beta ]
	[ "$(git -C backend/utilities/types show origin/main:config.json | jq -r .version)" = v0.1.1-beta ]

	# The switch happens once: the next run without the flag keeps beta and has nothing to do.
	rm scripts/.release-state
	run bash scripts/release-all.sh --dry-run
	[ "$status" -eq 0 ]
	[[ "$output" == *"$(printf '%-32s' api) v0.1.1-beta     -> v0.1.1-beta     unchanged"* ]]
}
