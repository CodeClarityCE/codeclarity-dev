#!/bin/sh
# Runs prettier --check on the given files with the version root package.json pins, downloaded
# from npm and checked against the sha512 pnpm-lock.yaml records. Needs node and tar.
# Usage (from the repo root): sh .cloud/scripts/prettier-check.sh <file>...
set -eu
version=$(node -p 'require("./package.json").devDependencies.prettier')
integrity=$(sed -n "/^  prettier@$version:\$/{n;s/.*integrity: \([^}]*\)}.*/\1/p;}" pnpm-lock.yaml)
[ -n "$integrity" ] || {
	echo "no prettier@$version in pnpm-lock.yaml" >&2
	exit 1
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Refuses the tarball unless its sha512 matches the lockfile's.
# shellcheck disable=SC2016 # the ${...} belong to the JavaScript, not the shell
node -e '
const [version, integrity, out] = process.argv.slice(1);
(async () => {
  const res = await fetch(`https://registry.npmjs.org/prettier/-/prettier-${version}.tgz`);
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const got = "sha512-" + require("crypto").createHash("sha512").update(body).digest("base64");
  if (got !== integrity) throw new Error(`prettier ${version} tarball is ${got}, pnpm-lock.yaml says ${integrity}`);
  require("fs").writeFileSync(out, body);
})().catch((e) => { console.error(e.message); process.exit(1); });
' "$version" "$integrity" "$work/prettier.tgz"
tar -xzf "$work/prettier.tgz" -C "$work"
node "$work/package/bin/prettier.cjs" --check "$@"
