"""Portability tests: env-overridable endpoint bases + host-agnostic slugs.

Endpoint bases are read once at module import, so each override test reloads
the target module under a monkeypatched environment (all HTTP is served by
httpx.MockTransport — no network). Restoration deliberately does NOT reload a
second time: a fresh reload would mint new dataclass types (ProjectSpec,
Snapshot) and break cross-module equality in the other test files, so the
fixture snapshots each module's __dict__ before the first reload and restores
it wholesale afterwards. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import orchestrator, sample, snapshots, triangulate  # noqa: E402

ENDPOINT_VARS = (
    "GH_API_BASE", "GH_RAW_BASE", "GH_WEB_BASE",
    "NPM_REGISTRY_BASE", "NPM_DOWNLOADS_BASE",
)


@pytest.fixture
def reload_with_env(monkeypatch):
    """Yield reload(module); on teardown undo the env changes first, then put
    back every reloaded module's original __dict__ (preserving the identity of
    its classes/functions for the rest of the session)."""
    saved: list[tuple[ModuleType, dict]] = []

    def _reload(module: ModuleType) -> ModuleType:
        if all(m is not module for m, _ in saved):
            saved.append((module, dict(module.__dict__)))
        return importlib.reload(module)

    yield _reload
    monkeypatch.undo()
    for module, state in reversed(saved):
        module.__dict__.clear()
        module.__dict__.update(state)


class Recorder:
    def __init__(self, handler) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)


def make_http(handler) -> tuple[httpx.Client, Recorder]:
    rec = Recorder(handler)
    http = httpx.Client(transport=httpx.MockTransport(rec), follow_redirects=True)
    return http, rec


# ---- env-overridable endpoint bases -----------------------------------------


def test_defaults_are_canonical_hosts(reload_with_env, monkeypatch):
    for var in ENDPOINT_VARS:
        monkeypatch.delenv(var, raising=False)
    reload_with_env(sample)
    reload_with_env(snapshots)
    reload_with_env(triangulate)
    assert sample.GITHUB_API == "https://api.github.com"
    assert sample.NPM_REGISTRY == "https://registry.npmjs.org"
    assert sample.NPM_DOWNLOADS_API == "https://api.npmjs.org/downloads/point/last-month"
    assert sample.GH_WEB_BASE == "https://github.com"
    assert snapshots.GITHUB_API == "https://api.github.com"
    assert triangulate.RAW_GITHUB == "https://raw.githubusercontent.com"


def test_empty_values_fall_through_to_defaults(reload_with_env, monkeypatch):
    # .env.example ships the vars present-but-empty; empty must mean default.
    for var in ENDPOINT_VARS:
        monkeypatch.setenv(var, "")
    reload_with_env(sample)
    reload_with_env(snapshots)
    reload_with_env(triangulate)
    assert sample.GITHUB_API == "https://api.github.com"
    assert snapshots.GITHUB_API == "https://api.github.com"
    assert triangulate.RAW_GITHUB == "https://raw.githubusercontent.com"


def test_trailing_slashes_are_stripped(reload_with_env, monkeypatch):
    monkeypatch.setenv("GH_API_BASE", "https://gh.example.test/api/")
    monkeypatch.setenv("GH_RAW_BASE", "https://raw.example.test//")
    reload_with_env(sample)
    reload_with_env(snapshots)
    reload_with_env(triangulate)
    assert sample.GITHUB_API == "https://gh.example.test/api"
    assert snapshots.GITHUB_API == "https://gh.example.test/api"
    assert triangulate.RAW_GITHUB == "https://raw.example.test"


def test_sample_requests_hit_overridden_github_api(reload_with_env, monkeypatch):
    monkeypatch.setenv("GH_API_BASE", "https://gh.example.test")
    reload_with_env(sample)
    http, rec = make_http(lambda r: httpx.Response(200, json={"full_name": "o/r"}))
    assert sample._repo_metadata(http, "o", "r") == {"full_name": "o/r"}
    assert str(rec.requests[0].url) == "https://gh.example.test/repos/o/r"


def test_npm_check_hits_overridden_bases(reload_with_env, monkeypatch):
    monkeypatch.setenv("NPM_REGISTRY_BASE", "https://registry.example.test/")
    monkeypatch.setenv("NPM_DOWNLOADS_BASE", "https://dl.example.test/point/last-month")
    reload_with_env(sample)
    http, rec = make_http(lambda r: httpx.Response(200, json={"downloads": 7}))
    assert sample._npm_check(http, "left-pad") == (True, 7)
    assert [str(r.url) for r in rec.requests] == [
        "https://registry.example.test/left-pad",
        "https://dl.example.test/point/last-month/left-pad",
    ]


def test_probe_clone_url_fallback_uses_gh_web_base(reload_with_env, monkeypatch):
    monkeypatch.setenv("GH_WEB_BASE", "https://git.example.test/")
    reload_with_env(sample)
    table: dict[str, object] = {
        # metadata WITHOUT html_url -> the fallback clone URL is constructed
        "/repos/octo/repo": {
            "full_name": "octo/repo", "owner": {"login": "octo"}, "name": "repo",
            "default_branch": "main",
            "fork": False, "archived": False, "disabled": False,
        },
        "/repos/octo/repo/contents/": [
            {"name": "package.json"}, {"name": "yarn.lock"},
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        payload = table.get(request.url.path)
        if payload is None:
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(200, json=payload)

    http, _ = make_http(handler)
    verdict = sample._ProbeCache(None).get_or_probe(http, "octo", "repo")
    assert verdict["qualifies"] is True
    assert verdict["canonical_url"] == "https://git.example.test/octo/repo"


def test_snapshots_client_targets_overridden_base(reload_with_env, monkeypatch):
    monkeypatch.setenv("GH_API_BASE", "https://gh.example.test")
    reload_with_env(snapshots)
    payload = [{"sha": "a" * 40, "commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}}]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=payload)

    # Spy on the module's own client construction so base_url is the module's
    # (overridden) GITHUB_API while transport stays mocked.
    real_client = httpx.Client

    def spy_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real_client(*a, **kw)

    monkeypatch.setattr(snapshots.httpx, "Client", spy_client)
    assert snapshots.resolve_head("o", "r", "main") == ("a" * 40, "2026-01-01T00:00:00Z")
    assert str(seen[0].url).startswith("https://gh.example.test/repos/o/r/commits")


# ---- host-agnostic slug handling --------------------------------------------


@pytest.mark.parametrize("url", [
    "https://github.com/facebook/react",
    "https://github.com/facebook/react/",
    "https://github.com/facebook/react.git",
    "git@github.com:facebook/react.git",
    "ssh://git@github.com/facebook/react.git",
    "https://git.example.test/facebook/react",
    "https://git.example.test:8443/facebook/react.git",
    "git@git.example.test:facebook/react.git",
    "git.example.test/facebook/react",
])
def test_parse_owner_repo_any_host(url):
    assert triangulate.parse_owner_repo(url) == ("facebook", "react")


@pytest.mark.parametrize("url", [
    "",
    "https://github.com/",
    "https://github.com/onlyowner",
    "not-a-url",
])
def test_parse_owner_repo_rejects_slugless_urls(url):
    assert triangulate.parse_owner_repo(url) is None


@pytest.mark.parametrize("url", [
    "https://github.com/o/r",
    "https://github.com/o/r.git",
    "https://git.example.test/o/r",
    "ssh://git@git.example.test/o/r.git",
])
def test_spec_from_record_derives_slug_from_any_host(url):
    rec = {"npm_name": "pkg", "rank": 1, "tier": "top-100",
           "git_url": url, "branch": "main"}
    spec = orchestrator._spec_from_record(rec)
    assert spec.github_owner == "o"
    assert spec.github_repo == "r"
    assert spec.git_url == url  # the submission URL itself is never rewritten
    assert spec.default_branch == "main"
