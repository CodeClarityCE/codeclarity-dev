"""Thin wrapper around the CodeClarity REST API for the JS vulnerability study.

Only the endpoints production code calls: auth, org/analyzer/integration
provisioning, project import, analysis create/get/list, raw result fetch,
batch delete, and knowledge provenance.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)


class CodeClarityError(RuntimeError):
    pass


class CodeClarityClient:
    def __init__(
        self,
        base_url: str,
        email: str,
        password: str,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._email = email
        self._password = password
        # Dev stack uses a self-signed cert; the study only ever targets a
        # local devcontainer or CI instance of it, so TLS verification is off
        # unconditionally rather than a knob nobody flips.
        self._http = httpx.Client(
            base_url=self.base_url,
            verify=False,
            timeout=timeout,
            follow_redirects=True,
        )
        self._token: str | None = None
        self._token_deadline: float = 0.0
        self._auth_lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "CodeClarityClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ---- auth ------------------------------------------------------------

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
            try:
                r = self._http.request(method, path, json=json, params=params, headers=headers)
            except httpx.TransportError as e:
                raise CodeClarityError(f"{method} {path}: transport error: {e}") from e
            if r.status_code == 401 and attempt == 0:
                self._token = None
                continue
            if r.status_code >= 400:
                raise CodeClarityError(f"{method} {path} -> {r.status_code}: {r.text[:500]}")
            if not r.text:
                return None
            return r.json()
        raise CodeClarityError(f"{method} {path}: auth retry exhausted")

    # ---- provisioning ------------------------------------------------------

    def _list_orgs(self) -> list[dict[str, Any]]:
        return self._request("GET", "/org", params={"page": 0, "entries_per_page": 100})["data"]

    def _ensure_org(self, name: str, description: str) -> str:
        for org in self._list_orgs():
            if org.get("name") == name:
                return org["id"]
        body = {"name": name, "description": description, "color_scheme": "1"}
        return self._request("POST", "/org", json=body)["id"]

    def get_analyzer_by_name(self, org_id: str, name: str) -> dict[str, Any] | None:
        page = 0
        while True:
            resp = self._request(
                "GET", f"/org/{org_id}/analyzers", params={"page": page, "entries_per_page": 100}
            )
            batch = resp.get("data") or []
            for a in batch:
                if a.get("name") == name:
                    return a
            if len(batch) < 100:
                return None
            page += 1

    def _ensure_analyzer(self, org_id: str, name: str, plugin_versions: dict[str, str]) -> str:
        existing = self.get_analyzer_by_name(org_id, name)
        if existing:
            return existing["id"]
        body = {
            "name": name,
            "description": (
                "JavaScript analyzer for the vulnerability-evolution study: "
                "js-sbom, vuln-finder, license-finder."
            ),
            "supported_languages": ["javascript"],
            "language_config": {
                "javascript": {"plugins": ["js-sbom", "vuln-finder", "license-finder"]},
            },
            "logo": "js",
            "steps": [
                [
                    {
                        "name": "js-sbom",
                        "version": plugin_versions["js-sbom"],
                        "config": {},
                        "persistant_config": {},
                    },
                ],
                [
                    {
                        "name": "vuln-finder",
                        "version": plugin_versions["vuln-finder"],
                        "config": {},
                        "persistant_config": {},
                    },
                    {
                        "name": "license-finder",
                        "version": plugin_versions["license-finder"],
                        "config": {"licensePolicy": []},
                        "persistant_config": {},
                    },
                ],
            ],
        }
        return self._request("POST", f"/org/{org_id}/analyzers", json=body)["id"]

    def _list_vcs_integrations(self, org_id: str) -> list[dict[str, Any]]:
        resp = self._request(
            "GET", f"/org/{org_id}/integrations/vcs", params={"page": 0, "entries_per_page": 100}
        )
        return resp.get("data") or []

    def _ensure_github_integration(self, org_id: str, token: str) -> str:
        for integ in self._list_vcs_integrations(org_id):
            if integ.get("integration_provider") == "GITHUB":
                return integ["id"]
        body = {"token": token, "token_type": "CLASSIC_TOKEN"}
        return self._request("POST", f"/org/{org_id}/integrations/github/add", json=body)["id"]

    def provision(
        self, org_name: str, analyzer_name: str, plugin_versions: dict[str, str], github_token: str
    ) -> tuple[str, str, str]:
        """Ensure the study's org/analyzer/GitHub-integration exist, by name,
        every call, deterministically, with no cache file. Returns
        (org_id, analyzer_id, integration_id)."""
        org_id = self._ensure_org(
            org_name, "Popularity-stratified study of JS vulnerability evolution."
        )
        analyzer_id = self._ensure_analyzer(org_id, analyzer_name, plugin_versions)
        integration_id = self._ensure_github_integration(org_id, github_token)
        return org_id, analyzer_id, integration_id

    # ---- projects ----------------------------------------------------------

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
                "GET", f"/org/{org_id}/projects", params={"page": page, "entries_per_page": 100}
            )
            batch = resp.get("data") or []
            out.extend(batch)
            if len(batch) < 100:
                return out
            page += 1

    def delete_projects(
        self, org_id: str, project_ids: list[str], batch_size: int = 500
    ) -> list[dict[str, str]]:
        """Bulk-delete via POST /org/{org}/projects/batch-delete: the API
        auto-cancels in-flight analyses and removes the clone tree itself."""
        results: list[dict[str, str]] = []
        for i in range(0, len(project_ids), batch_size):
            chunk = project_ids[i : i + batch_size]
            resp = self._request(
                "POST", f"/org/{org_id}/projects/batch-delete", json={"project_ids": chunk}
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
        # The downloader clones to DOWNLOAD_PATH/{org}/projects/{project}/{commit|branch}
        # (backend/services/downloader/receive.go, sbom_plugin_base.go).
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
        return self._request("POST", f"/org/{org_id}/projects/{project_id}/analyses", json=body)["id"]

    def get_analysis(self, org_id: str, project_id: str, analysis_id: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/org/{org_id}/projects/{project_id}/analyses/{analysis_id}"
        )["data"]

    def list_project_analyses(self, org_id: str, project_id: str) -> list[dict[str, Any]]:
        """Every analysis of one project, paginated: used by poll to check a
        project's whole pending batch in one or two calls instead of one GET
        per analysis."""
        out: list[dict[str, Any]] = []
        page = 0
        while True:
            resp = self._request(
                "GET",
                f"/org/{org_id}/projects/{project_id}/analyses",
                params={"page": page, "entries_per_page": 100},
            )
            batch = resp.get("data") or []
            out.extend(batch)
            if len(batch) < 100:
                return out
            page += 1

    def get_result(
        self, org_id: str, project_id: str, analysis_id: str, plugin_type: str
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
        """{"knowledge_sources": {...}, "epss_rows": int}."""
        return self._request("GET", "/knowledge/provenance")["data"]
