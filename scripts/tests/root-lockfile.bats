#!/usr/bin/env bats
# Tests root-lockfile.sh with a stand-in docker that logs its arguments and prints what pnpm would.
# The real pnpm runs in CI's root lockfile job.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
	write_file . pnpm-workspace.yaml $'packages:\n  - api\n  - "frontend"\n\nminimumReleaseAge: 4320'
	mkdir -p "$BATS_TEST_TMPDIR/bin"
	# DOCKER_OUT is printed, DOCKER_STATUS is the exit status.
	cat >"$BATS_TEST_TMPDIR/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_LOG"
[[ -n "${DOCKER_OUT:-}" ]] && printf '%s\n' "$DOCKER_OUT"
exit "${DOCKER_STATUS:-0}"
DOCKER
	chmod +x "$BATS_TEST_TMPDIR/bin/docker"
	export DOCKER_LOG="$BATS_TEST_TMPDIR/docker.log"
	PATH="$BATS_TEST_TMPDIR/bin:$PATH"
	unset GITHUB_ACTIONS
}

lockfile() {
	bash "$ROOT_DIR/scripts/root-lockfile.sh" "$@"
}

@test "check runs a frozen lockfile-only install on a read-only mount of the repo" {
	run lockfile check
	[ "$status" -eq 0 ]
	grep -qF -- "-v $ROOT_DIR:/repo:ro " "$DOCKER_LOG"
	grep -qF -- "-e FLAGS=--frozen-lockfile " "$DOCKER_LOG"
	grep -qF -- "-e MODE=check " "$DOCKER_LOG"
	grep -qF -- "corepack pnpm install --lockfile-only" "$DOCKER_LOG"
}

@test "the workspace packages come from pnpm-workspace.yaml" {
	run lockfile check
	[ "$status" -eq 0 ]
	grep -qF -- "-e PACKAGES=api frontend " "$DOCKER_LOG"
}

@test "update runs a plain lockfile-only install on a writable mount, as the calling user" {
	run lockfile update
	[ "$status" -eq 0 ]
	grep -qF -- "-v $ROOT_DIR:/repo -w /repo" "$DOCKER_LOG"
	grep -qF -- "-e FLAGS= " "$DOCKER_LOG"
	grep -qF -- "--user $(id -u):$(id -g) " "$DOCKER_LOG"
}

@test "it runs in the pinned Node image" {
	run lockfile check
	[ "$status" -eq 0 ]
	grep -qE -- " node:[0-9.]+-alpine@sha256:[0-9a-f]{64} sh -euc" "$DOCKER_LOG"
}

@test "a stale lockfile fails the check, keeps pnpm's list of mismatches and says how to fix it" {
	DOCKER_OUT=$'Error: ERR_PNPM_OUTDATED_LOCKFILE\n* in importers["api"]:\n  - amqplib (lockfile: 2.3.1, manifest: 2.4.0)' DOCKER_STATUS=1 run lockfile check
	[ "$status" -ne 0 ]
	[[ "$output" == *'in importers["api"]'*"amqplib (lockfile: 2.3.1, manifest: 2.4.0)"* ]]
	[[ "$output" == *"Run scripts/root-lockfile.sh update and commit pnpm-lock.yaml"* ]]
	[[ "$output" != *"::error"* ]]
}

@test "in GitHub Actions a stale lockfile also annotates pnpm-lock.yaml" {
	GITHUB_ACTIONS=true DOCKER_OUT='ERR_PNPM_OUTDATED_LOCKFILE' DOCKER_STATUS=1 run lockfile check
	[ "$status" -ne 0 ]
	[[ "$output" == *"::error file=pnpm-lock.yaml::"* ]]
}

@test "a version held back by minimumReleaseAge is reported as that, not as a stale lockfile" {
	DOCKER_OUT='amqplib@2.4.0 does not meet the minimumReleaseAge constraint' DOCKER_STATUS=1 run lockfile update
	[ "$status" -ne 0 ]
	[[ "$output" == *"pnpm refused a version published less than minimumReleaseAge"* ]]
	[[ "$output" != *"out of date"* ]]
}

@test "a check that fails before pnpm compares, such as a failed pull, is not called a stale lockfile" {
	DOCKER_OUT='Error response from daemon: pull access denied' DOCKER_STATUS=125 run lockfile check
	[ "$status" -ne 0 ]
	[[ "$output" == *"failed before pnpm could compare it"* ]]
	[[ "$output" != *"out of date"* ]]
}

@test "a failed update says so" {
	DOCKER_OUT='ERR_PNPM_FETCH_404' DOCKER_STATUS=1 run lockfile update
	[ "$status" -ne 0 ]
	[[ "$output" == *"pnpm could not regenerate the root pnpm-lock.yaml"* ]]
}

@test "an unknown mode prints usage and runs nothing" {
	run lockfile fix
	[ "$status" -eq 2 ]
	[[ "$output" == *"Usage: scripts/root-lockfile.sh check"* ]]
	[ ! -s "$DOCKER_LOG" ]
}
