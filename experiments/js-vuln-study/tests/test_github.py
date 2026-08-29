from __future__ import annotations

import httpx
import pytest

from js_vuln_study import github


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.github.com")


def test_auth_headers_with_and_without_token():
    assert "Authorization" not in github.auth_headers(None)
    assert github.auth_headers("tok")["Authorization"] == "Bearer tok"


def test_get_returns_immediately_on_200_404_409_422():
    def handler(request):
        code = int(request.url.params["code"])
        return httpx.Response(code, json={})

    http = _client(handler)
    for code in (200, 404, 409, 422):
        r = github.get(http, "/x", params={"code": code})
        assert r.status_code == code


def test_get_sleeps_until_rate_limit_reset(monkeypatch):
    calls = []
    slept = []
    monkeypatch.setattr(github.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(github.time, "time", lambda: 1000.0)

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1010"})
        return httpx.Response(200, json={"ok": True})

    http = _client(handler)
    r = github.get(http, "/x")
    assert r.status_code == 200
    assert len(calls) == 2
    assert slept == [pytest.approx(12.0)]  # reset(1010) - now(1000) + 2


def test_get_honours_retry_after_header(monkeypatch):
    slept = []
    monkeypatch.setattr(github.time, "sleep", lambda s: slept.append(s))
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200, json={})

    http = _client(handler)
    github.get(http, "/x")
    assert slept == [3.0]


def test_commit_before_returns_sha_and_date():
    def handler(request):
        assert request.url.params["sha"] == "main"
        assert request.url.params["per_page"] == "1"
        assert request.url.params["until"] == "2024-01-01T00:00:00+00:00"
        return httpx.Response(200, json=[{"sha": "abc123", "commit": {"committer": {"date": "2024-01-01T00:00:00Z"}}}])

    http = _client(handler)
    result = github.commit_before(http, "o", "r", "main", "2024-01-01T00:00:00+00:00")
    assert result == ("abc123", "2024-01-01T00:00:00Z")


def test_commit_before_none_on_404_and_409():
    for code in (404, 409):
        http = _client(lambda request, code=code: httpx.Response(code))
        assert github.commit_before(http, "o", "r", "main", None) is None


def test_commit_before_none_on_empty_list():
    http = _client(lambda request: httpx.Response(200, json=[]))
    assert github.commit_before(http, "o", "r", "main", None) is None


def test_commit_before_no_until_param_when_none():
    def handler(request):
        assert "until" not in request.url.params
        return httpx.Response(200, json=[{"sha": "x", "commit": {"committer": {"date": "d"}}}])

    github.commit_before(_client(handler), "o", "r", "main", None)


def test_list_commits_paginates_and_sorts():
    pages = {
        "1": [{"sha": f"c{i}", "commit": {"committer": {"date": f"2024-01-{i:02d}T00:00:00Z"}}} for i in range(100, 0, -1)],
        "2": [{"sha": "c0", "commit": {"committer": {"date": "2023-12-31T00:00:00Z"}}}],
    }

    def handler(request):
        page = request.url.params["page"]
        return httpx.Response(200, json=pages[page])

    out = github.list_commits(_client(handler), "o", "r", "lock.json", "2023-01-01", "2024-02-01")
    assert len(out) == 101
    assert out[0]["sha"] == "c0"
    assert out[-1]["date"] >= out[0]["date"]


def test_list_commits_empty_on_gone_repo():
    http = _client(lambda request: httpx.Response(404))
    assert github.list_commits(http, "o", "r", "lock.json", "s", "u") == []


def test_fetch_raw_none_on_404_bytes_on_200():
    http = _client(lambda request: httpx.Response(200 if "ok" in str(request.url) else 404, content=b"data"))
    assert github.fetch_raw(http, "/ok") == b"data"
    assert github.fetch_raw(http, "/missing") is None


def test_parse_owner_repo_host_agnostic():
    assert github.parse_owner_repo("https://github.com/facebook/react") == ("facebook", "react")
    assert github.parse_owner_repo("https://github.com/facebook/react.git") == ("facebook", "react")
    assert github.parse_owner_repo("https://internal.mirror/owner/repo") == ("owner", "repo")
    assert github.parse_owner_repo("not-a-url") is None
