"""Unit tests for the GitHub snapshot resolver.

All HTTP is served by httpx.MockTransport — no network. `resolve_head` /
`resolve_snapshots` construct their own client, so those tests monkeypatch
`httpx.Client` (via the module's `httpx` reference) to hand back a
mock-transport client built beforehand. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import snapshots  # noqa: E402
from js_vuln_study.snapshots import Snapshot, commit_before  # noqa: E402

SHA = "a" * 40
COMMIT_DATE = "2024-03-31T12:00:00Z"


def _commit_payload(sha: str = SHA, date: str = COMMIT_DATE) -> list[dict]:
    return [{"sha": sha, "commit": {"committer": {"date": date}}}]


class Recorder:
    """Routes requests to a handler while recording each one."""

    def __init__(self, handler) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)


def make_http(handler) -> tuple[httpx.Client, Recorder]:
    rec = Recorder(handler)
    http = httpx.Client(
        base_url="https://api.github.com", transport=httpx.MockTransport(rec)
    )
    return http, rec


def patch_client(monkeypatch, handler) -> Recorder:
    """Make the module's own `httpx.Client(...)` return a mock-backed client."""
    http, rec = make_http(handler)  # built BEFORE patching the constructor
    monkeypatch.setattr(snapshots.httpx, "Client", lambda *a, **kw: http)
    return rec


# ---- commit_before ----------------------------------------------------------


def test_commit_before_parses_sha_and_date():
    http, rec = make_http(lambda r: httpx.Response(200, json=_commit_payload()))
    out = commit_before(http, "o", "r", "2024-04-01T00:00:00+00:00", "main")
    assert out == (SHA, COMMIT_DATE)
    req = rec.requests[0]
    assert req.url.path == "/repos/o/r/commits"
    assert req.url.params["sha"] == "main"
    assert req.url.params["per_page"] == "1"
    assert req.url.params["until"] == "2024-04-01T00:00:00+00:00"


def test_commit_before_omits_until_for_branch_tip():
    http, rec = make_http(lambda r: httpx.Response(200, json=_commit_payload()))
    assert commit_before(http, "o", "r", None, "main") == (SHA, COMMIT_DATE)
    assert "until" not in rec.requests[0].url.params


@pytest.mark.parametrize("status", [404, 409])
def test_commit_before_404_and_409_return_none(status):
    http, _ = make_http(lambda r: httpx.Response(status, json={"message": "nope"}))
    assert commit_before(http, "o", "r", None, "main") is None


def test_commit_before_empty_history_returns_none():
    http, _ = make_http(lambda r: httpx.Response(200, json=[]))
    assert commit_before(http, "o", "r", "2020-01-01T00:00:00+00:00", "main") is None


# ---- resolve_snapshots --------------------------------------------------------


def test_resolve_snapshots_drops_predating_dates_and_appends_head(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/o/r":
            return httpx.Response(200, json={"default_branch": "dev"})
        assert request.url.path == "/repos/o/r/commits"
        assert request.url.params["sha"] == "dev"
        if request.url.params["until"].startswith("2022"):
            return httpx.Response(200, json=[])  # repo did not exist yet
        return httpx.Response(200, json=_commit_payload())

    patch_client(monkeypatch, handler)
    branch, snaps = snapshots.resolve_snapshots("o", "r", dates=["2022-01-01", "2024-04-01"])
    assert branch == "dev"
    assert [s.date for s in snaps] == ["2024-04-01", "HEAD"]
    assert snaps[0].commit_hash == SHA
    assert snaps[0].committed_at == COMMIT_DATE
    assert snaps[-1] == Snapshot(date="HEAD", commit_hash=None, committed_at=None)


def test_resolve_snapshots_missing_repo_yields_nothing(monkeypatch):
    patch_client(monkeypatch, lambda r: httpx.Response(404, json={"message": "gone"}))
    assert snapshots.resolve_snapshots("o", "r", dates=["2024-04-01"]) == (None, [])


def test_resolve_snapshots_can_skip_head(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/o/r":
            return httpx.Response(200, json={"default_branch": "main"})
        return httpx.Response(200, json=_commit_payload())

    patch_client(monkeypatch, handler)
    _, snaps = snapshots.resolve_snapshots(
        "o", "r", dates=["2024-04-01"], include_head=False
    )
    assert [s.date for s in snaps] == ["2024-04-01"]


# ---- resolve_head ---------------------------------------------------------------


def test_resolve_head_returns_branch_tip(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/o/r/commits"
        assert "until" not in request.url.params
        assert request.url.params["sha"] == "main"
        return httpx.Response(200, json=_commit_payload())

    patch_client(monkeypatch, handler)
    assert snapshots.resolve_head("o", "r", "main") == (SHA, COMMIT_DATE)


def test_resolve_head_missing_repo_is_none(monkeypatch):
    patch_client(monkeypatch, lambda r: httpx.Response(404, json={"message": "gone"}))
    assert snapshots.resolve_head("o", "r", "main") is None


# ---- _auth_headers ---------------------------------------------------------------


def test_auth_headers_prefers_github_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok-a")
    monkeypatch.setenv("GH_TOKEN", "tok-b")
    assert snapshots._auth_headers()["Authorization"] == "Bearer tok-a"


def test_auth_headers_falls_back_to_gh_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "tok-b")
    assert snapshots._auth_headers()["Authorization"] == "Bearer tok-b"


def test_auth_headers_absent_without_tokens(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    headers = snapshots._auth_headers()
    assert "Authorization" not in headers
    assert headers["Accept"] == "application/vnd.github+json"
