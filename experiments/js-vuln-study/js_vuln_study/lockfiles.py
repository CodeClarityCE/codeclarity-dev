"""Minimal root-lockfile parsers: lockfile bytes -> {package: {resolved versions}}.

One job only, for the remediation miner (`js_vuln_study.miner`): given the
raw bytes of a repository-root lockfile, return every resolved version each
package occurs at anywhere in the file. The accepted formats mirror what the
js-sbom plugin handles (root lockfile list from
`backend/plugins/js-sbom/src/utils/project_finder/PackageFileFinder.go`;
format edge cases cross-checked against its parsers):

  * package-lock.json, v1 (recursive `dependencies` tree) and v2/v3 (flat
    `packages` map keyed by `node_modules/` paths; scoped and nested names
    are the segment after the last `node_modules/`; the `""` root and
    workspace-definition keys carry no resolved dependency).
  * yarn.lock v1: the custom text format (`YarnLockV1Parser.go`); entry
    headers are comma-separated `name@range` descriptors, individually
    quotable (quotes may contain commas), followed by an indented
    `version "x"` line shared by every key of the entry.
  * yarn.lock berry (v2+): YAML with `__metadata`, `name@npm:range`
    descriptor keys; `@workspace:` descriptors are the workspaces themselves
    and are skipped.
  * pnpm-lock.yaml: YAML (PyYAML, added as a pinned dependency for the two
    YAML dialects rather than hand-parsing them); `packages` keys are
    `/name/version[_peer]` for lockfileVersion 5.x/7 and `/name@version[(peer)]`
    for 6.x/8 (bare `name@version` in 9's `packages`/`snapshots`), the same
    major-version dispatch as `PNPMParser.go`, plus `importers` direct deps.

Versions are the literal strings found in the lockfile; no semver
normalisation. The parsers are deliberately lossy (aliased descriptors keep
the alias name, exotic protocols are skipped): they only answer "which
resolved versions of package X does this root lockfile pin?", and raise
`LockfileParseError` on undecodable input rather than guessing.
"""

from __future__ import annotations

import json
import re

import yaml

# The js-sbom root-lockfile list (PackageFileFinder.go:91): the miner unions
# commit history across these three names to survive lockfile migrations.
ROOT_LOCKFILES = ["yarn.lock", "package-lock.json", "pnpm-lock.yaml"]

_YARN_V1_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_YARN_BERRY_RE = re.compile(r"^__metadata:", re.MULTILINE)


class LockfileParseError(ValueError):
    """Raised when lockfile bytes cannot be decoded/parsed at all."""


def parse_lockfile(name: str, data: bytes) -> dict[str, set[str]]:
    """Dispatch on the lockfile's filename. `name` must be a `ROOT_LOCKFILES`
    entry (npm-shrinkwrap.json is accepted as a package-lock alias)."""
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return parse_package_lock(data)
    if name == "yarn.lock":
        return parse_yarn(data)
    if name == "pnpm-lock.yaml":
        return parse_pnpm(data)
    raise LockfileParseError(f"unknown lockfile name: {name}")


def _add(out: dict[str, set[str]], name: str, version) -> None:
    if name and version is not None:
        version = str(version)
        if version:
            out.setdefault(name, set()).add(version)


# --------------------------------------------------------------------------- #
# package-lock.json (v1 tree / v2+v3 packages map)
# --------------------------------------------------------------------------- #

def parse_package_lock(data: bytes) -> dict[str, set[str]]:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise LockfileParseError(f"package-lock.json: {e}") from None
    if not isinstance(doc, dict):
        raise LockfileParseError("package-lock.json: not a JSON object")

    out: dict[str, set[str]] = {}
    packages = doc.get("packages")
    if isinstance(packages, dict):  # v2/v3
        for path, entry in packages.items():
            # "" (the root) and workspace-definition keys ("packages/app")
            # describe the project itself, not a resolved dependency. Link
            # entries carry no version and drop out naturally.
            if not isinstance(entry, dict) or "node_modules/" not in f"/{path}":
                continue
            _add(out, path.rpartition("node_modules/")[2], entry.get("version"))
        return out

    def walk(deps) -> None:  # v1: recursive dependencies tree
        if not isinstance(deps, dict):
            return
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            _add(out, name, entry.get("version"))
            walk(entry.get("dependencies"))

    walk(doc.get("dependencies"))
    return out


# --------------------------------------------------------------------------- #
# yarn.lock (v1 custom format / berry YAML)
# --------------------------------------------------------------------------- #

def _split_descriptors(header: str) -> list[str]:
    """Split a yarn entry header on commas, honouring double quotes: keys
    like `"pkg@>=1.0.0 <2.0.0", pkg@^1.2.0` contain commas inside quotes."""
    keys: list[str] = []
    buf: list[str] = []
    quoted = False
    for ch in header:
        if ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            keys.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    keys.append("".join(buf))
    return [k.strip() for k in keys if k.strip()]


def _descriptor_name(desc: str) -> str | None:
    """Package name of a `name@range` / `@scope/name@range` /
    `name@npm:range` descriptor (None for workspace descriptors)."""
    if "@workspace:" in desc:
        return None
    if "@npm:" in desc:  # berry: split before the protocol, works for scopes
        return desc.split("@npm:", 1)[0] or None
    idx = desc.rfind("@")
    if idx <= 0:  # bare name, or the leading @ of a range-less scoped name
        return desc or None
    return desc[:idx] or None


def parse_yarn(data: bytes) -> dict[str, set[str]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise LockfileParseError(f"yarn.lock: {e}") from None
    if _YARN_BERRY_RE.search(text):
        return _parse_yarn_berry(text)
    return _parse_yarn_v1(text)


def _parse_yarn_v1(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    current: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():  # entry header: `key1, key2:`
            header = line.rstrip().removesuffix(":")
            current = [
                n for n in (_descriptor_name(k) for k in _split_descriptors(header)) if n
            ]
        elif current:
            m = _YARN_V1_VERSION_RE.match(line)
            if m:
                for name in current:
                    _add(out, name, m.group(1))
    return out


def _parse_yarn_berry(text: str) -> dict[str, set[str]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise LockfileParseError(f"yarn.lock (berry): {e}") from None
    if not isinstance(doc, dict):
        raise LockfileParseError("yarn.lock (berry): not a mapping")
    out: dict[str, set[str]] = {}
    for key, entry in doc.items():
        if key == "__metadata" or not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if version is None:
            continue
        for desc in _split_descriptors(str(key)):
            name = _descriptor_name(desc)
            if name:
                _add(out, name, version)
    return out


# --------------------------------------------------------------------------- #
# pnpm-lock.yaml
# --------------------------------------------------------------------------- #

def _split_pnpm_key(key: str, path_dialect: bool) -> tuple[str, str] | None:
    """`packages`/`snapshots` key -> (name, version), or None when the key
    isn't a resolved package. `path_dialect` selects `/name/version` (5.x
    family) vs `/name@version` (6.x family and 9's bare keys)."""
    key = key.strip().removeprefix("/")
    if not key:
        return None
    if path_dialect:
        slash = key.rfind("/")
        if slash <= 0:
            return None
        name = key[:slash]
        version = key[slash + 1:].split("_", 1)[0]  # `_peer` suffix
    else:
        key = key.split("(", 1)[0]  # `(peer)` suffix groups
        at = key.rfind("@")
        if at <= 0:
            return None
        name, version = key[:at], key[at + 1:]
    return (name, version) if name and version else None


def parse_pnpm(data: bytes) -> dict[str, set[str]]:
    try:
        doc = yaml.safe_load(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, yaml.YAMLError) as e:
        raise LockfileParseError(f"pnpm-lock.yaml: {e}") from None
    if not isinstance(doc, dict):
        raise LockfileParseError("pnpm-lock.yaml: not a mapping")

    # Same major-version dispatch as PNPMParser.go: <=5 and 7 use the
    # `/name/version` path dialect, 6/8/9+ the `name@version` dialect.
    try:
        major = int(str(doc.get("lockfileVersion", "")).split(".")[0])
    except ValueError:
        major = 5
    path_dialect = major <= 5 or major == 7

    out: dict[str, set[str]] = {}
    for section in ("packages", "snapshots"):
        block = doc.get(section)
        if isinstance(block, dict):
            for key in block:
                nv = _split_pnpm_key(str(key), path_dialect)
                if nv:
                    _add(out, *nv)

    # Direct deps: per-importer blocks in workspaces, top-level otherwise.
    importers = doc.get("importers")
    blocks = list(importers.values()) if isinstance(importers, dict) else [doc]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for kind in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = block.get(kind)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                version = spec.get("version") if isinstance(spec, dict) else spec
                if not isinstance(version, (str, int, float)):
                    continue
                version = str(version)
                if version.startswith(("link:", "workspace:", "file:")):
                    continue
                _add(out, str(name), version.split("(", 1)[0].split("_", 1)[0])
    return out
