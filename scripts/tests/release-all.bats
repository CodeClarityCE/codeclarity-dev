#!/usr/bin/env bats
# Tests release-all.sh: version comparison, next-tag choice, releaser choice and version file,
# and that a releasing caller with CI_RELEASE off stops the whole run before any PR.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
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

# --- whole run ----------------------------------------------------------------------------

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
