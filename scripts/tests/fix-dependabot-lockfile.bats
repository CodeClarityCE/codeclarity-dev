#!/usr/bin/env bats
# Tests scripts/fix-dependabot-lockfile.sh against a local bare remote, with gh (stubs/) and
# pnpm (a stand-in written per test) stubbed. Nothing here reaches GitHub or the npm registry.
# Run from the repo root: bats scripts/tests

SCRIPT="$BATS_TEST_DIRNAME/../fix-dependabot-lockfile.sh"
BRANCH="dependabot/npm_and_yarn/develop/npm-abc123"

bats_require_minimum_version 1.5.0

setup() {
	export GIT_CONFIG_NOSYSTEM=1
	export GIT_CONFIG_GLOBAL="$BATS_TEST_TMPDIR/gitconfig"
	git config --global user.name "Test"
	git config --global user.email "test@example.invalid"
	export GH_STUB_LOG="$BATS_TEST_TMPDIR/gh.log"
	export GH_STUB_RULES="$BATS_TEST_TMPDIR/gh-rules.bash"
	export PNPM_LOG="$BATS_TEST_TMPDIR/pnpm.log"
	export FIX_LOCKFILE_CLONE_BASE="$BATS_TEST_TMPDIR/remotes"
	mkdir -p "$BATS_TEST_TMPDIR/bin" "$FIX_LOCKFILE_CLONE_BASE"
	PATH="$BATS_TEST_DIRNAME/stubs:$BATS_TEST_TMPDIR/bin:$PATH"
	: >"$GH_STUB_LOG"
	: >"$PNPM_LOG"
	pr_by app/dependabot
	stub_pnpm with-overrides
	make_remote
}

# A gh stand-in answering "pr view" for a PR by author $1 (open, same-repo branch).
pr_by() {
	cat >"$GH_STUB_RULES" <<EOF
gh_stub() {
	[[ "\$1 \$2" == "pr view" ]] || return 1
	printf '%s\t%s\t%s\t%s\n' "$1" "$BRANCH" false OPEN
}
EOF
}

# A pnpm stand-in. "with-overrides" writes a lockfile with an overrides block, "without" one
# without it. It logs each call and whether pnpm-workspace.yaml was staged at that point.
stub_pnpm() {
	cat >"$BATS_TEST_TMPDIR/bin/pnpm" <<EOF
#!/usr/bin/env bash
staged=no
[[ -f pnpm-workspace.yaml ]] && staged=yes
echo "\$* staged=\$staged" >>"\$PNPM_LOG"
[[ "\$*" == *--frozen-lockfile* ]] && exit 0
if [[ "$1" == with-overrides ]]; then
	printf 'lockfileVersion: 9.0\noverrides:\n  fastify: 5.12.8\n' >pnpm-lock.yaml
else
	printf 'lockfileVersion: 9.0\n' >pnpm-lock.yaml
fi
EOF
	chmod +x "$BATS_TEST_TMPDIR/bin/pnpm"
}

# A bare api remote whose Dependabot branch has a lockfile without overrides.
make_remote() {
	local src="$BATS_TEST_TMPDIR/src"
	git init -q -b "$BRANCH" "$src"
	mkdir -p "$src/.cloud/docker"
	printf 'overrides:\n  fastify: 5.12.8\n' >"$src/.cloud/docker/pnpm-workspace.yaml"
	printf 'pnpm-workspace.yaml\n' >"$src/.gitignore"
	printf 'lockfileVersion: 9.0\n' >"$src/pnpm-lock.yaml"
	git -C "$src" add -A
	# The real repos force-add it past the same ignore pattern.
	git -C "$src" add -f .cloud/docker/pnpm-workspace.yaml
	git -C "$src" commit -q -m "Bump the npm group"
	git clone -q --bare "file://$src" "$FIX_LOCKFILE_CLONE_BASE/api.git"
}

# The subject of the branch tip in the remote.
remote_tip() {
	git -C "$FIX_LOCKFILE_CLONE_BASE/api.git" log -1 --format=%s "$BRANCH"
}

@test "commits only the regenerated lockfile and pushes it to the PR branch" {
	run bash "$SCRIPT" api 212
	[ "$status" -eq 0 ]
	[ "$(remote_tip)" = "Restore pnpm overrides in lockfile" ]
	run git -C "$FIX_LOCKFILE_CLONE_BASE/api.git" show --name-only --format= "$BRANCH"
	[ "$output" = pnpm-lock.yaml ]
	grep -qF "pr view 212 -R CodeClarityCE/api" "$GH_STUB_LOG"
}

@test "stages the docker workspace file before running pnpm, without install scripts" {
	run bash "$SCRIPT" api 212
	[ "$status" -eq 0 ]
	grep -qxF "install --lockfile-only --ignore-scripts staged=yes" "$PNPM_LOG"
	run ! grep -q "staged=no" "$PNPM_LOG"
}

@test "dry run pushes nothing" {
	run bash "$SCRIPT" --dry-run api 212
	[ "$status" -eq 0 ]
	[[ "$output" == *"dry run"* ]]
	[ "$(remote_tip)" = "Bump the npm group" ]
}

@test "refuses a PR that Dependabot did not open" {
	pr_by someone
	run bash "$SCRIPT" api 212
	[ "$status" -eq 1 ]
	[[ "$output" == *"not Dependabot"* ]]
	[ ! -s "$PNPM_LOG" ]
}

@test "fails without pushing when the lockfile still has no overrides" {
	stub_pnpm without
	run bash "$SCRIPT" api 212
	[ "$status" -eq 1 ]
	[[ "$output" == *"no overrides block"* ]]
	[ "$(remote_tip)" = "Bump the npm group" ]
}

@test "rejects a repo other than api or frontend" {
	run bash "$SCRIPT" backend 1
	[ "$status" -eq 1 ]
	[[ "$output" == *"api or frontend"* ]]
}
