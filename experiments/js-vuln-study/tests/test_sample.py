"""Unit tests for the GitHub-stars sampler's pure/probe logic.

All HTTP is served by httpx.MockTransport — no network, and no full live
`build_sample` run: search results are stubbed and the module's own
`httpx.Client(...)` is monkeypatched to hand back a mock-backed client built
beforehand. Payloads are the minimal dicts the code actually reads. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import sample  # noqa: E402
from js_vuln_study.sample import _ProbeCache  # noqa: E402


def _meta(full_name: str = "octo/repo", branch: str = "main", **over) -> dict:
    owner, name = full_name.split("/")
    m = {
        "full_name": full_name,
        "owner": {"login": owner},
        "name": name,
        "default_branch": branch,
        "html_url": f"https://github.com/{full_name}",
        "fork": False,
        "archived": False,
        "disabled": False,
    }
    m.update(over)
    return m


def _hit(full_name: str, stars: int) -> dict:
    """A minimal /search/repositories item."""
    owner, name = full_name.split("/")
    return {
        "owner": {"login": owner},
        "name": name,
        "full_name": full_name,
        "stargazers_count": stars,
    }


def _b64_pkg(name: str) -> dict:
    raw = json.dumps({"name": name}).encode()
    return {"content": base64.b64encode(raw).decode()}


def _route(table: dict[str, object]):
    """Handler serving JSON 200s from a path->payload table; 404 otherwise."""

    def handler(request: httpx.Request) -> httpx.Response:
        payload = table.get(request.url.path)
        if payload is None:
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(200, json=payload)

    return handler


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


def _qualifying_routes(full_name: str, lockfile: str = "yarn.lock") -> dict:
    return {
        f"/repos/{full_name}": _meta(full_name),
        f"/repos/{full_name}/contents/": [
            {"name": "package.json"}, {"name": lockfile}, {"name": "README.md"},
        ],
        # /contents/package.json intentionally 404s -> no npm cross-check
    }


# ---- probe filtering ---------------------------------------------------------


@pytest.mark.parametrize("flag", ["fork", "archived", "disabled"])
def test_probe_rejects_fork_archived_disabled(flag):
    table = _qualifying_routes("octo/repo")
    table["/repos/octo/repo"] = _meta(**{flag: True})
    http, _ = make_http(_route(table))
    verdict = _ProbeCache(None).get_or_probe(http, "octo", "repo")
    assert verdict[flag] is True
    # the repo root itself qualifies — only the metadata flag drops it
    assert verdict["has_package_json"] is True
    assert verdict["has_lockfile"] is True
    assert verdict["qualifies"] is False


@pytest.mark.parametrize("lockfile", sample.LOCKFILES)
def test_probe_keeps_repo_with_any_lockfile(lockfile):
    http, _ = make_http(_route(_qualifying_routes("octo/repo", lockfile=lockfile)))
    verdict = _ProbeCache(None).get_or_probe(http, "octo", "repo")
    assert verdict["has_lockfile"] is True
    assert verdict["qualifies"] is True
    assert verdict["canonical_full_name"] == "octo/repo"


def test_probe_drops_repo_without_lockfile():
    table = _qualifying_routes("octo/repo")
    table["/repos/octo/repo/contents/"] = [{"name": "package.json"}, {"name": "README.md"}]
    http, _ = make_http(_route(table))
    verdict = _ProbeCache(None).get_or_probe(http, "octo", "repo")
    assert verdict["has_package_json"] is True
    assert verdict["has_lockfile"] is False
    assert verdict["qualifies"] is False


def test_probe_drops_repo_without_package_json():
    table = _qualifying_routes("octo/repo")
    table["/repos/octo/repo/contents/"] = [{"name": "yarn.lock"}]
    http, _ = make_http(_route(table))
    verdict = _ProbeCache(None).get_or_probe(http, "octo", "repo")
    assert verdict["qualifies"] is False


def test_probe_unresolvable_slug_is_recorded_dead():
    http, _ = make_http(_route({}))  # every path 404s
    verdict = _ProbeCache(None).get_or_probe(http, "octo", "gone")
    assert verdict == {
        "owner": "octo", "repo": "gone",
        "resolvable": False, "qualifies": False, "error": "unresolvable",
    }


# ---- canonical dedup (build_sample) --------------------------------------------


def test_build_sample_collapses_slugs_with_same_canonical_repo(monkeypatch):
    hits = [_hit("facebook/react", 200), _hit("react/react", 100)]
    monkeypatch.setattr(
        sample, "_search_repos",
        lambda http, lang, pages: hits if lang == "JavaScript" else [],
    )
    table = _qualifying_routes("facebook/react")
    # the stale slug's /repos metadata resolves (via redirect) to the canonical
    table["/repos/react/react"] = table["/repos/facebook/react"]
    http, _ = make_http(_route(table))
    monkeypatch.setattr(sample.httpx, "Client", lambda *a, **kw: http)

    specs = sample.build_sample(limit=10, output=None, probe_cache=None)
    assert [s.npm_name for s in specs] == ["facebook/react"]
    assert specs[0].rank == 0
    assert specs[0].github_owner == "facebook"
    assert specs[0].git_url == "https://github.com/facebook/react"


# ---- probe cache ------------------------------------------------------------------


def test_probe_cache_hit_avoids_network(tmp_path):
    cached = {
        "owner": "Octo", "repo": "Repo",  # keying is case-insensitive
        "resolvable": True, "qualifies": True,
        "canonical_full_name": "octo/repo",
    }
    path = tmp_path / "probe.jsonl"
    path.write_text(json.dumps(cached) + "\n", encoding="utf-8")

    http, rec = make_http(lambda r: httpx.Response(500, text="must not be called"))
    cache = _ProbeCache(path)
    assert cache.get_or_probe(http, "octo", "repo") == cached
    assert rec.requests == []  # cached slug -> zero requests
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1  # not re-appended


def test_probe_cache_refresh_unlinks_file_and_reprobes(tmp_path):
    # `run.py sample --refresh` unlinks the cache file before building: a fresh
    # _ProbeCache over the missing file starts empty and re-probes the network.
    path = tmp_path / "probe.jsonl"
    stale = {"owner": "octo", "repo": "repo", "resolvable": False,
             "qualifies": False, "error": "unresolvable"}
    path.write_text(json.dumps(stale) + "\n", encoding="utf-8")
    path.unlink()  # --refresh semantics (run.py cmd_sample)

    http, rec = make_http(_route(_qualifying_routes("octo/repo")))
    cache = _ProbeCache(path)
    verdict = cache.get_or_probe(http, "octo", "repo")
    assert len(rec.requests) > 0  # the stale verdict was NOT reused
    assert verdict["qualifies"] is True
    # the fresh verdict is persisted again for the next run
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["qualifies"] is True


# ---- min_npm_downloads --------------------------------------------------------------


def test_min_npm_downloads_drops_only_published_low_traffic(monkeypatch):
    hits = [
        _hit("o/low", 400),    # published, 10 downloads -> dropped
        _hit("o/high", 300),   # published, 5000 downloads -> kept
        _hit("o/unpub", 200),  # not on npm -> kept regardless
        _hit("o/null", 100),   # published, downloads unknown -> kept
    ]
    monkeypatch.setattr(
        sample, "_search_repos",
        lambda http, lang, pages: hits if lang == "JavaScript" else [],
    )
    npm_results = {
        "low-pkg": (True, 10),
        "high-pkg": (True, 5000),
        "unpub-pkg": (False, None),
        "null-pkg": (True, None),
    }
    monkeypatch.setattr(sample, "_npm_check", lambda http, name: npm_results[name])

    table: dict[str, object] = {}
    for slug, pkg in [("o/low", "low-pkg"), ("o/high", "high-pkg"),
                      ("o/unpub", "unpub-pkg"), ("o/null", "null-pkg")]:
        table[f"/repos/{slug}"] = _meta(slug)
        table[f"/repos/{slug}/contents/"] = [
            {"name": "package.json"}, {"name": "package-lock.json"},
        ]
        table[f"/repos/{slug}/contents/package.json"] = _b64_pkg(pkg)
    http, _ = make_http(_route(table))
    monkeypatch.setattr(sample.httpx, "Client", lambda *a, **kw: http)

    specs = sample.build_sample(
        limit=10, output=None, probe_cache=None, min_npm_downloads=1000
    )
    assert [s.npm_name for s in specs] == ["o/high", "o/unpub", "o/null"]
    by_name = {s.npm_name: s for s in specs}
    assert by_name["o/high"].npm_pkg == "high-pkg"
    assert by_name["o/high"].npm_downloads == 5000
    assert by_name["o/unpub"].npm_pkg is None  # npm_pkg only kept when published
    assert by_name["o/null"].npm_downloads is None
