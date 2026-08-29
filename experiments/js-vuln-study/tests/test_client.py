"""Tests for the CodeClarity REST client against real response shapes.

`GET /org` wraps each row in a membership envelope ({role, joined_on,
organization: {id, name, ...}}), unlike `GET /org/{id}/analyzers` and
`GET /org/{id}/integrations/vcs`, which are flat. This file exists because
that mismatch went unnoticed for a long time: the old harness cached the
provisioned org id in `data/setup.json` after the first successful call, so
`_ensure_org` (then `ensure_org`) ran its list-and-match loop only once ever
per machine and its shape bug never mattered in practice. Removing that
cache (this study calls `provision()` on every `run`) turned a latent bug
into one that fires on every invocation: `_ensure_org` never matched an
existing org by name and created a fresh one each time.
"""

from __future__ import annotations

import httpx
import pytest

from js_vuln_study.client import CodeClarityClient, CodeClarityError


def _client(handler) -> CodeClarityClient:
    c = CodeClarityClient("https://x", "e@x.com", "p")
    c._http = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://x")
    c._token = "tok"
    c._token_deadline = 1e18
    return c


def test_ensure_org_finds_an_existing_org_inside_the_membership_envelope():
    """GET /org returns [{"role":..., "organization": {"id","name",...}}, ...]."""
    calls = []

    def handler(request):
        calls.append((request.method, str(request.url)))
        if request.method == "GET" and request.url.path == "/org":
            return httpx.Response(200, json={"data": [
                {"role": 0, "organization": {"id": "org-1", "name": "js-vuln-study-top100"}},
            ]})
        if request.method == "POST" and request.url.path == "/org":
            pytest.fail("must not create a new org when one already matches by name")
        return httpx.Response(404)

    client = _client(handler)
    org_id = client._ensure_org("js-vuln-study-top100", "desc")
    assert org_id == "org-1"
    assert not any(m == "POST" for m, _ in calls)


def test_ensure_org_creates_when_no_name_matches():
    def handler(request):
        if request.method == "GET" and request.url.path == "/org":
            return httpx.Response(200, json={"data": [
                {"role": 0, "organization": {"id": "org-1", "name": "someone-elses-org"}},
            ]})
        if request.method == "POST" and request.url.path == "/org":
            return httpx.Response(201, json={"id": "org-new"})
        return httpx.Response(404)

    client = _client(handler)
    assert client._ensure_org("js-vuln-study-top100", "desc") == "org-new"


def test_provision_reuses_org_analyzer_integration_across_two_calls():
    """The regression that motivated this file: two `provision()` calls (as
    two `run` invocations would make, with no setup.json cache) must return
    the SAME org/analyzer/integration ids, not create duplicates."""
    state = {"orgs": [], "analyzers": [], "integrations": []}

    def handler(request):
        path, method = request.url.path, request.method
        if path == "/org" and method == "GET":
            return httpx.Response(200, json={"data": [
                {"role": 0, "organization": {"id": o["id"], "name": o["name"]}} for o in state["orgs"]
            ]})
        if path == "/org" and method == "POST":
            import json as _json
            payload = _json.loads(request.content)
            org = {"id": f"org-{len(state['orgs']) + 1}", "name": payload["name"]}
            state["orgs"].append(org)
            return httpx.Response(201, json={"id": org["id"]})
        if path.endswith("/analyzers") and method == "GET":
            return httpx.Response(200, json={"data": list(state["analyzers"])})
        if path.endswith("/analyzers") and method == "POST":
            import json as _json
            payload = _json.loads(request.content)
            analyzer = {"id": f"az-{len(state['analyzers']) + 1}", "name": payload["name"], "steps": []}
            state["analyzers"].append(analyzer)
            return httpx.Response(201, json={"id": analyzer["id"]})
        if path.endswith("/integrations/vcs") and method == "GET":
            return httpx.Response(200, json={"data": list(state["integrations"])})
        if path.endswith("/integrations/github/add") and method == "POST":
            integ = {"id": f"integ-{len(state['integrations']) + 1}", "integration_provider": "GITHUB"}
            state["integrations"].append(integ)
            return httpx.Response(201, json={"id": integ["id"]})
        return httpx.Response(404)

    client = _client(handler)
    plugins = {"js-sbom": "v1", "vuln-finder": "v1", "license-finder": "v1"}
    first = client.provision("js-vuln-study-top100", "js-vuln-study-v2", plugins, "tok")
    second = client.provision("js-vuln-study-top100", "js-vuln-study-v2", plugins, "tok")
    assert first == second
    assert len(state["orgs"]) == 1
    assert len(state["analyzers"]) == 1
    assert len(state["integrations"]) == 1


def test_start_analysis_body_pins_project_path_and_merges_config():
    captured = {}

    def handler(request):
        if request.url.path.endswith("/analyses") and request.method == "POST":
            import json as _json
            captured["body"] = _json.loads(request.content)
            return httpx.Response(201, json={"id": "an-1"})
        return httpx.Response(404)

    client = _client(handler)
    client.start_analysis(
        org_id="org-1", project_id="proj-1", analyzer_id="az-1", branch="main",
        commit_hash="a" * 40, config={"vuln-finder": {"knowledge_asof": "2026-08-03"}},
    )
    body = captured["body"]
    assert body["config"]["js-sbom"]["project"] == "org-1/projects/proj-1/" + "a" * 40
    assert body["config"]["vuln-finder"]["knowledge_asof"] == "2026-08-03"
    assert body["commit_hash"] == "a" * 40


def test_request_wraps_transport_errors():
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    client = _client(handler)
    with pytest.raises(CodeClarityError, match="transport error"):
        client.get_analysis("org-1", "proj-1", "an-1")
