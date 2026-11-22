#!/usr/bin/env bats
# Tests same-named-branches.sh: on a PR it checks out the PR's branch in each submodule that has it
# and develop in the others, nested ones included, and keeps the pointers when no submodule has it.
# The submodules' remotes are local bare repos. Run from the repo root: bats scripts/tests

setup() {
	ROOT_DIR="$BATS_TEST_TMPDIR/root"
	REMOTES="$BATS_TEST_TMPDIR/remotes"
	export GIT_CONFIG_NOSYSTEM=1
	export GIT_CONFIG_GLOBAL="$BATS_TEST_TMPDIR/gitconfig"
	git config --global user.name "Test"
	git config --global user.email "test@example.invalid"
	git config --global advice.detachedHead false
	git config --global protocol.file.allow always
	mkdir -p "$ROOT_DIR/scripts" "$REMOTES"
	cp "$BATS_TEST_DIRNAME/../same-named-branches.sh" "$ROOT_DIR/scripts/"
	for repo in api deployment backend js-sbom; do
		remote_repo "$repo"
	done
	# backend nests js-sbom, as it nests the plugins.
	add_submodule "$REMOTES/backend.git" js-sbom plugins/js-sbom
	git -C "$ROOT_DIR" init -q -b develop
	for repo in api deployment backend; do
		git -C "$ROOT_DIR" submodule add -q "$REMOTES/$repo.git" "$repo"
	done
	git -C "$ROOT_DIR" submodule update -q --init --recursive
	git -C "$ROOT_DIR" commit -q -m "Add the submodules"
	# develop moves on past the pointers in every repo.
	for repo in api deployment backend js-sbom; do
		push_commit "$repo" develop
	done
}

# A bare remote <name>.git with main and develop on one commit.
remote_repo() {
	local work="$BATS_TEST_TMPDIR/work/$1"
	git init -q --bare -b develop "$REMOTES/$1.git"
	git init -q -b main "$work"
	git -C "$work" commit -q --allow-empty -m "Initial commit"
	git -C "$work" remote add origin "$REMOTES/$1.git"
	git -C "$work" push -q origin main main:develop
}

# Adds <repo> as submodule <path> on develop of the remote <parent>.
add_submodule() {
	local work="$BATS_TEST_TMPDIR/work/add-$2"
	git clone -q -b develop "$1" "$work"
	git -C "$work" submodule add -q "$REMOTES/$2.git" "$3"
	git -C "$work" commit -q -m "Add $3"
	git -C "$work" push -q origin develop
}

# Pushes a new commit to <branch> of <repo>'s remote, branching from develop.
push_commit() {
	local work="$BATS_TEST_TMPDIR/work/$1"
	git -C "$work" fetch -q origin
	git -C "$work" checkout -q -B "$2" "origin/$(git -C "$work" ls-remote --heads origin "$2" | grep -q . && echo "$2" || echo develop)"
	git -C "$work" commit -q --allow-empty -m "Change $1 on $2"
	git -C "$work" push -q origin "HEAD:$2"
}

# The commit <branch> of <repo>'s remote points at.
tip() {
	git --git-dir "$REMOTES/$1.git" rev-parse "refs/heads/$2"
}

# The commit checked out at <path> in the umbrella.
head_at() {
	git -C "$ROOT_DIR/$1" rev-parse HEAD
}

resolve() {
	(cd "$ROOT_DIR" && bash scripts/same-named-branches.sh "$@")
}

@test "uses the PR branch where a submodule has it and develop elsewhere, nested submodules included" {
	push_commit api feat/x
	push_commit js-sbom feat/x

	run resolve feat/x

	[ "$status" -eq 0 ]
	[ "$(head_at api)" = "$(tip api feat/x)" ]
	[ "$(head_at backend/plugins/js-sbom)" = "$(tip js-sbom feat/x)" ]
	[ "$(head_at deployment)" = "$(tip deployment develop)" ]
	[ "$(head_at backend)" = "$(tip backend develop)" ]
}

@test "the log lists which submodules used the PR branch and which fell back to develop" {
	push_commit api feat/x
	push_commit js-sbom feat/x

	run resolve feat/x

	[ "$status" -eq 0 ]
	[[ "$output" =~ api\ +PR\ branch\ feat/x ]]
	[[ "$output" =~ backend/plugins/js-sbom\ +PR\ branch\ feat/x ]]
	[[ "$output" =~ deployment\ +develop\ \(fallback\) ]]
	[[ "$output" =~ backend\ +develop\ \(fallback\) ]]
}

@test "keeps the pointers when no submodule has the PR branch" {
	pointer=$(head_at deployment)

	run resolve feat/nowhere

	[ "$status" -eq 0 ]
	[ "$(head_at deployment)" = "$pointer" ]
	[[ "$output" == *"No submodule has branch feat/nowhere"* ]]
}

@test "keeps the pointers on a push, and on a PR from develop or main" {
	pointer=$(head_at deployment)

	for branch in "" develop main; do
		run resolve "$branch"

		[ "$status" -eq 0 ]
		[ "$(head_at deployment)" = "$pointer" ]
		[[ "$output" == *"keeping the submodule pointers"* ]]
	done
}

# Prints "<file> <job> <ok|missing>" for each job with a recursive checkout, ok when the next step runs the script.
recursive_checkout_jobs() {
	local file
	for file in "$@"; do
		awk -v file="$file" '
			/^  [A-Za-z0-9_-]+:$/ { if (pending) print file, job, "missing"; job = $1; sub(":", "", job); pending = 0; next_step = 0 }
			/submodules: recursive/ { pending = 1; next }
			pending && /^      - / { if (next_step) { print file, job, "missing"; pending = 0 } else next_step = 1 }
			pending && next_step && /same-named-branches\.sh/ { print file, job, "ok"; pending = 0; next_step = 0 }
			END { if (pending) print file, job, "missing" }
		' "$file"
	done
}

# The PR workflows (ci.yml and the real-stack workflow it calls) and the nightly API fuzz. knowledge-dump.yml runs only on main.
@test "every PR job with a recursive submodule checkout resolves the same-named branches next" {
	cd "$BATS_TEST_DIRNAME/../.."
	run recursive_checkout_jobs .github/workflows/ci.yml .github/workflows/e2e-real-stack.yml .github/workflows/api-fuzz.yml

	echo "$output"
	[ "$(grep -c ' ok$' <<<"$output")" -ge 6 ]
	[[ "$output" != *" missing"* ]]
}

@test "skips a .gitmodules entry that has no gitlink, and names it in the log" {
	# backend's .gitmodules keeps an entry whose submodule was removed from its tree.
	local work="$BATS_TEST_TMPDIR/work/backend"
	git -C "$work" fetch -q origin
	git -C "$work" checkout -q -B develop origin/develop
	git -C "$work" config -f .gitmodules submodule.common-types.path common-types
	git -C "$work" config -f .gitmodules submodule.common-types.url "$REMOTES/api.git"
	git -C "$work" commit -q -am "Leave a stale entry"
	git -C "$work" push -q origin develop
	push_commit js-sbom feat/x

	run resolve feat/x

	[ "$status" -eq 0 ]
	[ "$(head_at backend/plugins/js-sbom)" = "$(tip js-sbom feat/x)" ]
	[[ "$output" == *"Skipping backend/common-types"* ]]
}
