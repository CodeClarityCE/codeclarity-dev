# Shared fixtures for the scripts/ bats tests: a fake umbrella tree whose repos push to local
# bare remotes, and the stand-in gh in stubs/. Nothing here reaches GitHub or Docker.

# A fake tree with a copy of the scripts, a one-module backend/go.work, and an isolated git config.
setup_fake_root() {
	ROOT_DIR="$BATS_TEST_TMPDIR/root"
	REMOTES="$BATS_TEST_TMPDIR/remotes"
	export GH_STUB_ROOT="$ROOT_DIR"
	export GH_STUB_DIR="$BATS_TEST_TMPDIR/gh"
	export GH_STUB_LOG="$BATS_TEST_TMPDIR/gh.log"
	export GH_STUB_RULES="$BATS_TEST_TMPDIR/gh-rules.bash"
	PATH="$BATS_TEST_DIRNAME/stubs:$PATH"

	export GIT_CONFIG_NOSYSTEM=1
	export GIT_CONFIG_GLOBAL="$BATS_TEST_TMPDIR/gitconfig"
	git config --global user.name "Test"
	git config --global user.email "test@example.invalid"
	git config --global advice.detachedHead false

	mkdir -p "$ROOT_DIR/scripts" "$REMOTES" "$GH_STUB_DIR"
	cp "$BATS_TEST_DIRNAME"/../*.sh "$ROOT_DIR/scripts/"
	: >"$GH_STUB_LOG"
	write_file backend go.work $'go 1.27.4\n\nuse (\n\t./utilities/types\n)'
	write_file backend/utilities/types go.mod $'module github.com/CodeClarityCE/utility-types\n\ngo 1.27.4'
}

# Runs one function of scripts/<script> in a fresh bash, with the fake tree's copy sourced.
sourced() {
	bash -c 's=$1; shift; args=("$@"); set --; source "$s"; "${args[@]}"' _ "$ROOT_DIR/scripts/$1" "${@:2}"
}

# Runs one release-all.sh function.
rel() {
	sourced release-all.sh "$@"
}

# Writes <content> to <path> in repo <key>, without committing.
write_file() {
	mkdir -p "$(dirname "$ROOT_DIR/$1/$2")"
	printf '%s\n' "$3" >"$ROOT_DIR/$1/$2"
}

# Makes <key> a repo with a local bare origin, main and develop on one commit, develop checked out.
init_repo() {
	local dir="$ROOT_DIR/$1" remote="$REMOTES/${1//\//_}.git"
	[[ "$1" == . ]] && remote="$REMOTES/root.git"
	mkdir -p "$dir"
	git -C "$dir" init -q -b main
	git -C "$dir" commit -q --allow-empty -m "Initial commit"
	git init -q --bare "$remote"
	git -C "$dir" remote add origin "$remote"
	git -C "$dir" push -q -u origin main
	git -C "$dir" checkout -q -b develop
	git -C "$dir" push -q -u origin develop
}

# Writes a file in <key>, commits it on develop and pushes develop.
commit_file() {
	write_file "$@"
	git -C "$ROOT_DIR/$1" add -- "$2"
	git -C "$ROOT_DIR/$1" commit -q -m "Change $2"
	git -C "$ROOT_DIR/$1" push -q origin develop
}

# Moves origin's main to develop, as a merged release PR would.
merge_to_main() {
	git -C "$ROOT_DIR/$1" push -q origin develop:main
	git -C "$ROOT_DIR/$1" fetch -q origin
}

# Tags origin's main as <tag>.
tag_main() {
	git -C "$ROOT_DIR/$1" tag "$2" origin/main
	git -C "$ROOT_DIR/$1" push -q origin "$2"
}

# Gives <key> a CI caller that uses the central <workflow>, e.g. go-image.yml.
caller() {
	write_file "$1" .github/workflows/ci.yml "jobs:
  build:
    uses: CodeClarityCE/.github/.github/workflows/$2@v1"
}

# Sets a repo variable as gh reports it, e.g. CI_RELEASE true.
set_variable() {
	mkdir -p "$GH_STUB_DIR/$1/variables"
	printf '%s\n' "$3" >"$GH_STUB_DIR/$1/variables/$2"
}
