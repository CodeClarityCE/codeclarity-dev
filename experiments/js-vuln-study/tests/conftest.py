"""Shared test fixtures. `pyproject.toml` sets `pythonpath = ["."]`, so no
test file needs a `sys.path.insert` hack."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from js_vuln_study import manifest as manifest_mod
from js_vuln_study.config import Study

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def row(**overrides) -> manifest_mod.Row:
    defaults = dict(
        npm_name="@vue/runtime-core", tier="top100", rank=0,
        git_url="https://github.com/vuejs/core", branch="main",
        snapshot_date="HEAD", commit_hash="a" * 40, committed_at="2026-07-01T00:00:00Z",
        project_id="af919e72-f691-47de-a8bf-77a5e7f2cca5",
        analysis_id="7cd19dee-35cd-45fe-a42a-8032e5facec0",
        state="done",
    )
    defaults.update(overrides)
    return manifest_mod.Row(**defaults)


def write_manifest(path: Path, rows: list[manifest_mod.Row]) -> None:
    manifest_mod.write_all(path, rows)


def write_tables(
    tables_dir: Path,
    analyses_rows: list[dict],
    vulns_rows: list[dict],
    run_meta: dict | None = None,
    events_rows: list[dict] | None = None,
) -> None:
    tables_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(analyses_rows).to_parquet(tables_dir / "analyses.parquet", index=False)
    pd.DataFrame(vulns_rows).to_parquet(tables_dir / "vulns.parquet", index=False)
    if run_meta is not None:
        (tables_dir / "run_meta.json").write_text(json.dumps(run_meta), encoding="utf-8")
    if events_rows is not None:
        pd.DataFrame(events_rows).to_parquet(tables_dir / "remediation_events.parquet", index=False)


@pytest.fixture
def study(tmp_path) -> Study:
    d = tmp_path / "study"
    d.mkdir()
    (d / "study.toml").write_text(
        '[study]\nname = "t"\nretries = 2\n', encoding="utf-8"
    )
    (d / "sample.json").write_text("[]", encoding="utf-8")
    return Study.load(d)


class FakeAnalysis(dict):
    pass


class FakeAPI:
    """A duck-typed CodeClarityClient double for pipeline tests.

    Records import_project/start_analysis calls; analysis status is
    scripted per analysis_id via `set_status`; `get_result` serves the two
    fixture blobs by default.
    """

    def __init__(self) -> None:
        self.imported: dict[str, str] = {}  # git_url -> project_id
        self.import_calls: list[dict] = []
        self.start_calls: list[dict] = []
        self._analyses: dict[str, dict] = {}
        self._next_analysis = 0
        self._next_project = 0
        self.deleted: list[str] = []

    def import_project(self, org_id, url, name, description, integration_id=None) -> str:
        self.import_calls.append({"org_id": org_id, "url": url, "name": name, "integration_id": integration_id})
        if url not in self.imported:
            self._next_project += 1
            self.imported[url] = f"proj-{self._next_project}"
        return self.imported[url]

    def start_analysis(self, org_id, project_id, analyzer_id, branch, commit_hash=None, config=None) -> str:
        self._next_analysis += 1
        aid = f"an-{self._next_analysis}"
        self.start_calls.append({
            "org_id": org_id, "project_id": project_id, "analyzer_id": analyzer_id,
            "branch": branch, "commit_hash": commit_hash, "config": config,
        })
        self._analyses[aid] = {"id": aid, "project_id": project_id, "status": "completed", "steps": []}
        return aid

    def set_status(self, analysis_id: str, status: str, failure_reason: str | None = None) -> None:
        self._analyses[analysis_id]["status"] = status
        if failure_reason is not None:
            self._analyses[analysis_id]["failure_reason"] = failure_reason

    def get_analysis(self, org_id, project_id, analysis_id) -> dict:
        return self._analyses[analysis_id]

    def list_project_analyses(self, org_id, project_id) -> list[dict]:
        return [a for a in self._analyses.values() if a["project_id"] == project_id]

    def get_result(self, org_id, project_id, analysis_id, plugin_type) -> dict:
        from js_vuln_study.client import CodeClarityError

        name = {"js-sbom": "js-sbom.json", "vuln-finder": "vuln-finder.json"}.get(plugin_type)
        if name is None or not (FIXTURES / name).exists():
            raise CodeClarityError("no result")
        return json.loads((FIXTURES / name).read_text())

    def get_knowledge_provenance(self) -> dict:
        return {"knowledge_sources": {"nvd": "2026-08-01T00:00:00Z"}, "epss_rows": 100}

    def get_analyzer_by_name(self, org_id, name):
        return {"id": "analyzer-1", "steps": [[{"name": "js-sbom", "version": "v1"}]]}

    def delete_projects(self, org_id, project_ids, batch_size=500):
        self.deleted.extend(project_ids)
        return [{"id": pid, "status": "deleted"} for pid in project_ids]

    def provision(self, org_name, analyzer_name, plugin_versions, github_token):
        return "org-1", "analyzer-1", "integration-1"


@pytest.fixture
def fake_api() -> FakeAPI:
    return FakeAPI()
