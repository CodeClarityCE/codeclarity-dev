"""Thin wrapper around the CodeClarity REST API for the JS vulnerability study.

Only the endpoints the experiment needs: auth, org, analyzer, project import,
analysis create/get, and raw result fetch.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Plugin versions baked into a *newly created* analyzer. They must match the
# tags of the deployed backend/plugins/* binaries; run_meta.jsonl records what
# actually ran (the analyzer steps are read back at submit time).
PLUGIN_VERSIONS = {
    "js-sbom": "v0.0.25-alpha",
    "vuln-finder": "v0.0.25-alpha",
    "license-finder": "v0.0.18-alpha",
}


class CodeClarityError(RuntimeError):
    pass


class CodeClarityClient:
    def __init__(
        self,
        base_url: str,
        email: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._email = email
        self._password = password
        self._http = httpx.Client(
            base_url=self.base_url,
            verify=verify_tls,
            timeout=timeout,
            follow_redirects=True,
        )
        self._token: str | None = None
        self._token_deadline: float = 0.0
        # The httpx.Client is thread-safe, but re-login mutates _token /
        # _token_deadline; the lock keeps concurrent submit workers from
        # racing a refresh (worst case without it: token torn between threads).
        self._auth_lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "CodeClarityClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ---- auth ----------------------------------------------------------------

    def _login(self) -> None:
        r = self._http.post(
            "/auth/authenticate",
            json={"email": self._email, "password": self._password},
        )
        if r.status_code >= 400:
            raise CodeClarityError(f"auth failed: {r.status_code} {r.text}")
        data = r.json()["data"]
        self._token = data["token"]
        # JWT TTL is 90 min; refresh 10 min early.
        self._token_deadline = time.time() + 80 * 60
        log.info("authenticated as %s", self._email)

    def _auth_headers(self) -> dict[str, str]:
        with self._auth_lock:
            if self._token is None or time.time() >= self._token_deadline:
                self._login()
            return {"Authorization": f"Bearer {self._token}"}

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        for attempt in range(2):
            headers = self._auth_headers()
            r = self._http.request(method, path, json=json, params=params, headers=headers)
            if r.status_code == 401 and attempt == 0:
                self._token = None  # force re-login on next iteration
                continue
            if r.status_code >= 400:
                raise CodeClarityError(
                    f"{method} {path} -> {r.status_code}: {r.text[:500]}"
                )
            if not r.text:
                return None
            return r.json()
        raise CodeClarityError(f"{method} {path}: auth retry exhausted")

    # ---- organizations -------------------------------------------------------

    def list_orgs(self) -> list[dict[str, Any]]:
        return self._request("GET", "/org", params={"page": 0, "entries_per_page": 100})["data"]

    def create_org(self, name: str, description: str, color_scheme: str = "1") -> str:
        body = {"name": name, "description": description, "color_scheme": color_scheme}
        return self._request("POST", "/org", json=body)["id"]

    def ensure_org(self, name: str, description: str) -> str:
        for org in self.list_orgs():
            if org.get("name") == name:
                return org["id"]
        return self.create_org(name, description)

    # ---- analyzers -----------------------------------------------------------

    def create_analyzer(self, org_id: str, body: dict[str, Any]) -> str:
        return self._request("POST", f"/org/{org_id}/analyzers", json=body)["id"]

    def get_analyzer_by_name(self, org_id: str, name: str) -> dict[str, Any] | None:
        # The `/analyzers/name` endpoint 500s on miss (repo throws generic Error),
        # so enumerate instead — orgs never have more than a handful of analyzers.
        page = 0
        while True:
            resp = self._request(
                "GET",
                f"/org/{org_id}/analyzers",
                params={"page": page, "entries_per_page": 100},
            )
            batch = resp.get("data") or []
            for a in batch:
                if a.get("name") == name:
                    return a
            if len(batch) < 100:
                return None
            page += 1

    def ensure_js_analyzer(self, org_id: str, name: str = "js-vuln-study-v2") -> str:
        existing = self.get_analyzer_by_name(org_id, name)
        if existing:
            return existing["id"]
        body = {
            "name": name,
            "description": (
                "JavaScript analyzer for the vulnerability-evolution study: "
                "js-sbom, vuln-finder, license-finder. (js-patching is "
                "temporarily disabled — known bug, data is untrustworthy.)"
            ),
            "supported_languages": ["javascript"],
            "language_config": {
                "javascript": {
                    "plugins": ["js-sbom", "vuln-finder", "license-finder"],
                },
            },
            "logo": "js",
            "steps": [
                [
                    {
                        "name": "js-sbom",
                        "version": PLUGIN_VERSIONS["js-sbom"],
                        "config": {},
                        "persistant_config": {},
                    },
                ],
                [
                    {
                        "name": "vuln-finder",
                        "version": PLUGIN_VERSIONS["vuln-finder"],
                        "config": {},
                        "persistant_config": {},
                    },
                    {
                        "name": "license-finder",
                        "version": PLUGIN_VERSIONS["license-finder"],
                        "config": {"licensePolicy": []},
                        "persistant_config": {},
                    },
                ],
            ],
        }
        return self.create_analyzer(org_id, body)

    # ---- integrations --------------------------------------------------------

    def list_vcs_integrations(self, org_id: str) -> list[dict[str, Any]]:
        resp = self._request(
            "GET",
            f"/org/{org_id}/integrations/vcs",
            params={"page": 0, "entries_per_page": 100},
        )
        return resp.get("data") or []

    def add_github_integration(self, org_id: str, token: str) -> str:
        """Register a GitHub classic PAT (scope: public_repo or repo).

        The server validates the token against GitHub's API on creation; an
        invalid or scopeless token surfaces as a 400 IntegrationInvalidToken or
        IntegrationTokenMissingPermissions.
        """
        body = {"token": token, "token_type": "CLASSIC_TOKEN"}
        return self._request(
            "POST",
            f"/org/{org_id}/integrations/github/add",
            json=body,
        )["id"]

    def ensure_github_integration(self, org_id: str, token: str) -> str:
        for integ in self.list_vcs_integrations(org_id):
            if integ.get("integration_provider") == "GITHUB":
                return integ["id"]
        return self.add_github_integration(org_id, token)

    # ---- projects ------------------------------------------------------------

    def import_project(
        self,
        org_id: str,
        url: str,
        name: str,
        description: str,
        integration_id: str | None = None,
    ) -> str:
        body: dict[str, Any] = {"url": url, "name": name, "description": description}
        if integration_id:
            body["integration_id"] = integration_id
        return self._request("POST", f"/org/{org_id}/projects", json=body)["id"]

    def list_projects(self, org_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 0
        while True:
            resp = self._request(
                "GET",
                f"/org/{org_id}/projects",
                params={"page": page, "entries_per_page": 100},
            )
            batch = resp.get("data") or []
            out.extend(batch)
            if len(batch) < 100:
                return out
            page += 1

    def delete_project(self, org_id: str, project_id: str) -> None:
        """Delete a single project (cascade)."""
        self._request("DELETE", f"/org/{org_id}/projects/{project_id}")

    def delete_projects(
        self,
        org_id: str,
        project_ids: list[str],
        batch_size: int = 500,
    ) -> list[dict[str, str]]:
        """Bulk-delete projects via POST /org/{org}/projects/batch-delete.

        The API auto-cancels each project's in-flight analyses and removes them
        in bounded batches. ``batch_size`` chunks the request id list to stay at
        or under the API's per-call cap (500). Returns the concatenated per-id
        result objects ({"id", "status"}).
        """
        results: list[dict[str, str]] = []
        for i in range(0, len(project_ids), batch_size):
            chunk = project_ids[i : i + batch_size]
            resp = self._request(
                "POST",
                f"/org/{org_id}/projects/batch-delete",
                json={"project_ids": chunk},
            )
            results.extend(resp["data"]["results"])
        return results

    # ---- analyses ------------------------------------------------------------

    def start_analysis(
        self,
        org_id: str,
        project_id: str,
        analyzer_id: str,
        branch: str,
        commit_hash: str | None = None,
        config: dict[str, dict[str, Any]] | None = None,
    ) -> str:
        # js-sbom reads the on-disk project path from config["js-sbom"]["project"].
        # The downloader clones to  DOWNLOAD_PATH/{org}/projects/{project}/{commit or branch}.
        # (See backend/services/downloader/receive.go:73-77 and backend/utilities/
        # boilerplates/sbom_plugin_base.go:118-144.)
        path_leaf = commit_hash if commit_hash else branch
        project_path = f"{org_id}/projects/{project_id}/{path_leaf}"
        merged: dict[str, dict[str, Any]] = {
            "js-sbom": {"project": project_path, "branch": branch},
            "vuln-finder": {},
            "license-finder": {"licensePolicy": []},
        }
        if config:
            for plugin, plugin_cfg in config.items():
                merged.setdefault(plugin, {}).update(plugin_cfg)
        body: dict[str, Any] = {
            "analyzer_id": analyzer_id,
            "config": merged,
            "branch": branch,
            "schedule_type": "once",
            "languages": ["javascript"],
        }
        if commit_hash:
            body["commit_hash"] = commit_hash
        return self._request(
            "POST",
            f"/org/{org_id}/projects/{project_id}/analyses",
            json=body,
        )["id"]

    def get_analysis(self, org_id: str, project_id: str, analysis_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/org/{org_id}/projects/{project_id}/analyses/{analysis_id}",
        )["data"]

    def cancel_analyses(
        self,
        org_id: str,
        project_id: str,
        analysis_ids: list[str],
        batch_size: int = 500,
    ) -> list[dict[str, str]]:
        """Cancel in-flight analyses so workers stop advancing them.

        Non-terminal analyses transition to 'cancelled'; already-terminal ones
        are reported as 'skipped'. Returns the per-id result objects.
        """
        results: list[dict[str, str]] = []
        for i in range(0, len(analysis_ids), batch_size):
            chunk = analysis_ids[i : i + batch_size]
            resp = self._request(
                "POST",
                f"/org/{org_id}/projects/{project_id}/analyses/batch-cancel",
                json={"analysis_ids": chunk},
            )
            results.extend(resp["data"]["results"])
        return results

    def get_result(
        self,
        org_id: str,
        project_id: str,
        analysis_id: str,
        plugin_type: str,
    ) -> Any:
        return self._request(
            "GET",
            "/result",
            params={
                "org_id": org_id,
                "project_id": project_id,
                "analysis_id": analysis_id,
                "type": plugin_type,
            },
        )["data"]

    # ---- knowledge -------------------------------------------------------------

    def get_knowledge_provenance(self) -> dict[str, Any]:
        """Knowledge-DB freshness for provenance capture.

        Shape: {"knowledge_sources": {"<source>": "<ISO ts or null>", ...},
        "epss_rows": <int>}. 404s on APIs that predate the endpoint — callers
        must tolerate that.
        """
        return self._request("GET", "/knowledge/provenance")["data"]


# The Go backend writes AnalysisStatus values that differ from the TypeScript
# enum in api/: {success, completed, failure, started, ongoing, updating_db}.
# We treat completed/success as terminal-happy and failure/failed as terminal-sad.
# updating_db is non-terminal — the analysis will resume once the knowledge DB
# refresh notifies the dispatcher.
TERMINAL_STATUSES = {"completed", "success", "failure", "failed"}
