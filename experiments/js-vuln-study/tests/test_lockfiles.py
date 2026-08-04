"""Unit tests for the minimal root-lockfile parsers.

Each fixture under tests/fixtures/lockfiles/ is a small but realistic file
exercising the format's edge cases (scoped packages, multiple resolved
versions, yarn-v1 multi-key headers with quoted commas, both pnpm key
dialects). No network. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import lockfiles  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lockfiles"


def _load(fixture: str, name: str) -> dict[str, set[str]]:
    return lockfiles.parse_lockfile(name, (FIXTURES / fixture).read_bytes())


# ---- package-lock.json ------------------------------------------------------


def test_package_lock_v1_walks_nested_dependencies():
    got = _load("package-lock-v1.json", "package-lock.json")
    assert got["lodash"] == {"4.17.20"}
    assert got["@babel/core"] == {"7.12.3"}
    # top-level semver AND the copy nested under @babel/core
    assert got["semver"] == {"7.3.2", "5.7.1"}


def test_package_lock_v3_packages_map():
    got = _load("package-lock-v3.json", "package-lock.json")
    assert got["lodash"] == {"4.17.21"}
    assert got["@babel/core"] == {"7.23.0"}
    # nested node_modules path resolves to the leaf name; both copies collected
    assert got["semver"] == {"7.5.4", "6.3.1"}
    # the "" root and the workspace definition are not resolved dependencies,
    # and the link entry has no version
    assert "" not in got
    assert "packages/app" not in got
    assert "@fixture/app" not in got


def test_package_lock_rejects_garbage():
    with pytest.raises(lockfiles.LockfileParseError):
        lockfiles.parse_lockfile("package-lock.json", b"not json {")


# ---- yarn.lock v1 -----------------------------------------------------------


def test_yarn_v1_multi_key_headers_and_scopes():
    got = _load("yarn-v1.lock", "yarn.lock")
    assert got["@babel/core"] == {"7.12.3"}
    # two entries for lodash -> both resolved versions retained
    assert got["lodash"] == {"4.17.20", "3.10.1"}
    assert got["semver"] == {"5.7.1", "7.3.2"}


def test_yarn_v1_quoted_key_with_comma_inside_range():
    text = b'"pkg@>=1.0.0 <2.0.0", pkg@^1.2.0:\n  version "1.4.0"\n'
    assert lockfiles.parse_lockfile("yarn.lock", text) == {"pkg": {"1.4.0"}}


def test_yarn_v1_dependencies_block_is_not_a_version():
    # `semver "^5.4.1"` under a dependencies: block must not register 5.4.1
    got = _load("yarn-v1.lock", "yarn.lock")
    assert "^5.4.1" not in got.get("semver", set())


# ---- yarn.lock berry --------------------------------------------------------


def test_yarn_berry_descriptors_and_workspace_skip():
    got = _load("yarn-berry.lock", "yarn.lock")
    assert got["@babel/core"] == {"7.23.0"}
    assert got["lodash"] == {"4.17.21"}
    assert got["semver"] == {"6.3.1", "7.5.4"}
    assert "fixture-workspace" not in got  # @workspace: descriptor skipped


# ---- pnpm-lock.yaml ---------------------------------------------------------


def test_pnpm_v5_path_dialect_with_peer_suffix():
    got = _load("pnpm-v5.yaml", "pnpm-lock.yaml")
    assert got["lodash"] == {"4.17.20"}
    assert got["@babel/core"] == {"7.12.3"}
    assert got["react-dom"] == {"17.0.2"}  # `_react@17.0.2` peer suffix stripped
    assert got["semver"] == {"5.7.1"}


def test_pnpm_v6_at_dialect_importers_and_peer_groups():
    got = _load("pnpm-v6.yaml", "pnpm-lock.yaml")
    assert got["lodash"] == {"4.17.21"}
    assert got["@babel/core"] == {"7.23.0"}  # `(supports-color@9.4.0)` stripped
    assert got["semver"] == {"7.5.4"}
    assert "@fixture/local" not in got  # link: version skipped


def test_pnpm_v9_bare_keys_and_snapshots():
    got = _load("pnpm-v9.yaml", "pnpm-lock.yaml")
    assert got["lodash"] == {"4.17.21"}
    assert got["@babel/core"] == {"7.24.0"}
    assert got["semver"] == {"6.3.1"}


def test_pnpm_rejects_garbage():
    with pytest.raises(lockfiles.LockfileParseError):
        lockfiles.parse_lockfile("pnpm-lock.yaml", b"a: [unclosed")


# ---- dispatch ---------------------------------------------------------------


def test_unknown_lockfile_name_raises():
    with pytest.raises(lockfiles.LockfileParseError):
        lockfiles.parse_lockfile("Gemfile.lock", b"")


def test_root_lockfiles_matches_js_sbom_list():
    # PackageFileFinder.go:91 — keep in sync with the plugin's walker.
    assert lockfiles.ROOT_LOCKFILES == ["yarn.lock", "package-lock.json", "pnpm-lock.yaml"]
