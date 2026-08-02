"""Unit tests for the CodeClarity API client.

All HTTP is served by httpx.MockTransport — no network. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study.client import CodeClarityClient, CodeClarityError  # noqa: E402

BASE = "https://cc.test/api"
ORG = "e8467209-05fc-40b5-8217-a9127d1a14a4"
PROJ = "af919e72-f691-47de-a8bf-77a5e7f2cca5"


class Recorder:
    """Routes requests to a handler while recording every (method, path, body)."""

    def __init__(self, handler) -> None:
        self.requests: list[httpx.Request] = []
        self.logins = 0
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/authenticate"):
            self.logins += 1
            return httpx.Response(200, json={"data": {"token": f"tok{self.logins}"}})
        self.requests.append(request)
        return self._handler(request)

    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests]


def make_client(handler) -> tuple[CodeClarityClient, Recorder]:
    rec = Recorder(handler)
    client = CodeClarityClient(BASE, "u@example.com", "pw")
    client._http.close()
    client._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(rec))
    return client, rec


# ---- auth -----------------------------------------------------------------


def test_login_attaches_bearer_token():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer tok1"
        return httpx.Response(200, json={"data": []})

    client, rec = make_client(handler)
    assert client.list_orgs() == []
    assert rec.logins == 1


def test_login_failure_raises():
    client, _ = make_client(lambda r: httpx.Response(200))
    client._http = httpx.Client(
        base_url=BASE,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(401, text="bad credentials")
        ),
    )
    with pytest.raises(CodeClarityError, match="auth failed: 401"):
        client.list_orgs()


def test_401_mid_session_relogs_in_once_and_retries():
    state = {"served_401": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if not state["served_401"]:
            state["served_401"] = True
            return httpx.Response(401, text="expired")
        assert request.headers["Authorization"] == "Bearer tok2"
        return httpx.Response(200, json={"data": [{"id": ORG, "name": "x"}]})

    client, rec = make_client(handler)
    assert client.list_orgs() == [{"id": ORG, "name": "x"}]
    assert rec.logins == 2  # initial + exactly one re-login
    assert len(rec.requests) == 2  # the 401'd call + its retry


def test_second_consecutive_401_raises():
    client, rec = make_client(lambda r: httpx.Response(401, text="still expired"))
    with pytest.raises(CodeClarityError, match="401"):
        client.list_orgs()
    assert rec.logins == 2
    assert len(rec.requests) == 2  # no third attempt


def test_error_body_truncated_to_500_chars():
    body = "x" * 499 + "Y" + "OVERFLOW" * 100
    client, _ = make_client(lambda r: httpx.Response(500, text=body))
    with pytest.raises(CodeClarityError) as exc:
        client.list_orgs()
    msg = str(exc.value)
    assert "x" * 499 + "Y" in msg
    assert "OVERFLOW" not in msg


def test_empty_response_body_returns_none():
    client, _ = make_client(lambda r: httpx.Response(200, text=""))
    assert client.delete_project(ORG, PROJ) is None


# ---- chunking -----------------------------------------------------------------


def test_delete_projects_chunks_at_500():
    def handler(request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["project_ids"]
        return httpx.Response(200, json={
            "data": {"results": [{"id": i, "status": "deleted"} for i in ids]},
        })

    client, rec = make_client(handler)
    ids = [f"p{i}" for i in range(1001)]
    results = client.delete_projects(ORG, ids)
    assert len(rec.requests) == 3
    assert all(r.url.path.endswith(f"/org/{ORG}/projects/batch-delete") for r in rec.requests)
    sizes = [len(b["project_ids"]) for b in rec.bodies()]
    assert sizes == [500, 500, 1]
    # payloads partition the input in order, nothing dropped or duplicated
    assert [i for b in rec.bodies() for i in b["project_ids"]] == ids
    assert [r["id"] for r in results] == ids


def test_cancel_analyses_chunks_at_500():
    def handler(request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["analysis_ids"]
        return httpx.Response(200, json={
            "data": {"results": [{"id": i, "status": "cancelled"} for i in ids]},
        })

    client, rec = make_client(handler)
    ids = [f"a{i}" for i in range(1001)]
    results = client.cancel_analyses(ORG, PROJ, ids)
    assert len(rec.requests) == 3
    assert all(
        r.url.path.endswith(f"/org/{ORG}/projects/{PROJ}/analyses/batch-cancel")
        for r in rec.requests
    )
    assert [len(b["analysis_ids"]) for b in rec.bodies()] == [500, 500, 1]
    assert len(results) == 1001


def test_delete_projects_custom_batch_size():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"results": []}})

    client, rec = make_client(handler)
    client.delete_projects(ORG, [f"p{i}" for i in range(5)], batch_size=2)
    assert [len(b["project_ids"]) for b in rec.bodies()] == [2, 2, 1]


# ---- start_analysis --------------------------------------------------------------


def _analysis_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"id": "new-analysis"})


def test_start_analysis_body_with_commit():
    client, rec = make_client(_analysis_handler)
    aid = client.start_analysis(ORG, PROJ, "anlz", branch="main", commit_hash="c" * 40)
    assert aid == "new-analysis"
    body = rec.bodies()[0]
    # the js-sbom project leaf is the commit when one is pinned
    assert body["config"]["js-sbom"]["project"] == f"{ORG}/projects/{PROJ}/{'c' * 40}"
    assert body["config"]["js-sbom"]["branch"] == "main"
    assert body["commit_hash"] == "c" * 40
    assert body["branch"] == "main"
    assert body["analyzer_id"] == "anlz"
    assert body["schedule_type"] == "once"
    assert body["languages"] == ["javascript"]


def test_start_analysis_body_without_commit():
    client, rec = make_client(_analysis_handler)
    client.start_analysis(ORG, PROJ, "anlz", branch="develop")
    body = rec.bodies()[0]
    assert body["config"]["js-sbom"]["project"] == f"{ORG}/projects/{PROJ}/develop"
    assert "commit_hash" not in body  # key present only when a commit is pinned


def test_start_analysis_merges_caller_config():
    client, rec = make_client(_analysis_handler)
    client.start_analysis(
        ORG, PROJ, "anlz", branch="main",
        config={"js-sbom": {"extra": 1}, "custom-plugin": {"a": 2}},
    )
    cfg = rec.bodies()[0]["config"]
    assert cfg["js-sbom"]["extra"] == 1
    assert cfg["js-sbom"]["branch"] == "main"  # defaults survive the merge
    assert cfg["custom-plugin"] == {"a": 2}
    assert cfg["license-finder"] == {"licensePolicy": []}


# ---- org / analyzer lookup ---------------------------------------------------------


def test_ensure_org_returns_existing_id_without_create():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, json={"data": [
            {"id": "other", "name": "other-org"},
            {"id": ORG, "name": "js-vuln-study-2026"},
        ]})

    client, rec = make_client(handler)
    assert client.ensure_org("js-vuln-study-2026", "desc") == ORG
    assert [r.method for r in rec.requests] == ["GET"]


def test_ensure_org_creates_when_missing():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"data": []})
        return httpx.Response(200, json={"id": "fresh-org"})

    client, rec = make_client(handler)
    assert client.ensure_org("js-vuln-study-2026", "desc") == "fresh-org"
    assert [r.method for r in rec.requests] == ["GET", "POST"]
    assert json.loads(rec.requests[1].content)["name"] == "js-vuln-study-2026"


def test_get_analyzer_by_name_paginates_to_match():
    page0 = [{"id": f"a{i}", "name": f"other-{i}"} for i in range(100)]
    page1 = [{"id": "target-id", "name": "js-vuln-study-v2"}]

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        return httpx.Response(200, json={"data": [page0, page1][page]})

    client, rec = make_client(handler)
    found = client.get_analyzer_by_name(ORG, "js-vuln-study-v2")
    assert found == {"id": "target-id", "name": "js-vuln-study-v2"}
    assert len(rec.requests) == 2


def test_get_analyzer_by_name_miss_returns_none():
    client, rec = make_client(
        lambda r: httpx.Response(200, json={"data": [{"id": "a", "name": "nope"}]})
    )
    assert client.get_analyzer_by_name(ORG, "js-vuln-study-v2") is None
    assert len(rec.requests) == 1  # short page -> no further pagination


def test_list_projects_paginates_and_concatenates():
    page0 = [{"id": f"p{i}"} for i in range(100)]
    page1 = [{"id": "p100"}]

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        return httpx.Response(200, json={"data": [page0, page1][page]})

    client, _ = make_client(handler)
    assert len(client.list_projects(ORG)) == 101


# ---- knowledge provenance -------------------------------------------------------


def test_get_knowledge_provenance_returns_data_dict():
    payload = {"knowledge_sources": {"nvd": "2026-08-01T00:00:00Z"}, "epss_rows": 123}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/knowledge/provenance")
        return httpx.Response(200, json={"data": payload})

    client, _ = make_client(handler)
    assert client.get_knowledge_provenance() == payload


def test_get_knowledge_provenance_404_raises_codeclarity_error():
    # Actual contract: a 404 (older API without the endpoint) surfaces as
    # CodeClarityError; provenance.py catches it and falls back to Postgres.
    client, _ = make_client(lambda r: httpx.Response(404, text="Not Found"))
    with pytest.raises(CodeClarityError, match="404"):
        client.get_knowledge_provenance()
