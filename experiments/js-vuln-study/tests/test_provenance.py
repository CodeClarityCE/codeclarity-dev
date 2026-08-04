"""Unit tests for run-provenance capture.

The API client is a duck-typed fake and `subprocess.run` is monkeypatched to a
deterministic git stub — no API, no network, no real git repos (except the
negative-path test, which points real git at a nonexistent directory). Run
with: cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import provenance  # noqa: E402
from js_vuln_study.client import CodeClarityError  # noqa: E402
from js_vuln_study.orchestrator import POLL_TIMEOUT, STARTED_TIMEOUT  # noqa: E402
from js_vuln_study.snapshots import SNAPSHOT_DATES  # noqa: E402

ORG = "e8467209-05fc-40b5-8217-a9127d1a14a4"
ANALYZER = "7cd19dee-35cd-45fe-a42a-8032e5facec0"

KNOWLEDGE = {"knowledge_sources": {"nvd": "2026-08-01T00:00:00Z"}, "epss_rows": 42}
STEPS = [
    [{"name": "js-sbom", "version": "v0.0.13", "config": {"ignored": True}}],
    [{"name": "vuln-finder", "version": "v0.0.14"}],
]


class FakeClient:
    """Duck-typed CodeClarityClient covering the two calls provenance makes."""

    def __init__(self, knowledge=KNOWLEDGE, analyzer="default", raise_knowledge=False):
        if analyzer == "default":
            analyzer = {"id": ANALYZER, "name": "js-vuln-study-v2", "steps": STEPS}
        self._knowledge = knowledge
        self._analyzer = analyzer
        self._raise = raise_knowledge

    def get_knowledge_provenance(self):
        if self._raise:
            raise CodeClarityError("GET /api/knowledge/provenance -> 404: Not Found")
        return self._knowledge

    def get_analyzer_by_name(self, org_id, name):
        return self._analyzer


def _fake_git_run(dirty_repos: set[str]):
    """subprocess.run stub: sha-<dirname> for rev-parse, porcelain per repo."""

    def run(cmd, **kwargs):
        assert cmd[:2] == ["git", "-C"]
        repo = Path(cmd[2])
        if cmd[3] == "rev-parse":
            return SimpleNamespace(returncode=0, stdout=f"sha-{repo.name}\n", stderr="")
        if cmd[3] == "status":
            out = " M some/file\n" if repo.name in dirty_repos else ""
            return SimpleNamespace(returncode=0, stdout=out, stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    return run


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """Fake repo root (dirty) with an api/package.json, wired as REPO_ROOT."""
    root = tmp_path / "repo"
    (root / "api").mkdir(parents=True)
    (root / "api" / "package.json").write_text(json.dumps({"version": "9.9.9"}))
    monkeypatch.setattr(provenance, "REPO_ROOT", root)
    monkeypatch.setattr(provenance.subprocess, "run", _fake_git_run({"repo"}))
    monkeypatch.delenv("JS_VULN_ANALYZER_NAME", raising=False)
    return root


# ---- capture_run_meta --------------------------------------------------------


def test_capture_run_meta_record_shape(fake_repo, tmp_path):
    data_dir = tmp_path / "data"
    meta = provenance.capture_run_meta(
        FakeClient(), ORG, ANALYZER, data_dir, extra={"cmd": "submit", "limit": 3}
    )

    assert meta["experiment_sha"] == "sha-repo"
    assert meta["experiment_dirty"] is True
    assert meta["api_sha"] == "sha-api"
    assert meta["backend_sha"] == "sha-backend"
    assert meta["api_version"] == "9.9.9"
    assert meta["org_id"] == ORG
    assert meta["analyzer_id"] == ANALYZER
    # read-back keeps only name/version per step, dropping extra fields
    assert meta["analyzer_steps"] == [
        [{"name": "js-sbom", "version": "v0.0.13"}],
        [{"name": "vuln-finder", "version": "v0.0.14"}],
    ]
    assert meta["knowledge"] == KNOWLEDGE
    assert meta["config"] == {
        "snapshot_dates": list(SNAPSHOT_DATES),
        "poll_timeout": POLL_TIMEOUT,
        "started_timeout": STARTED_TIMEOUT,
    }
    # extra= merged into the record
    assert meta["cmd"] == "submit"
    assert meta["limit"] == 3
    assert "ts" in meta and "run_id" in meta

    lines = (data_dir / provenance.RUN_META_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1  # exactly one line per call
    assert json.loads(lines[0]) == meta


def test_capture_run_meta_appends_one_line_per_call(fake_repo, tmp_path):
    data_dir = tmp_path / "data"
    first = provenance.capture_run_meta(FakeClient(), ORG, ANALYZER, data_dir)
    second = provenance.capture_run_meta(FakeClient(), ORG, ANALYZER, data_dir)
    lines = (data_dir / provenance.RUN_META_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert first["run_id"] != second["run_id"]
    assert [json.loads(l)["run_id"] for l in lines] == [first["run_id"], second["run_id"]]


def test_capture_falls_back_to_postgres_then_nulls(fake_repo, tmp_path, monkeypatch, caplog):
    calls = []

    def fake_pg():
        calls.append(1)
        return None

    monkeypatch.setattr(provenance, "_knowledge_via_postgres", fake_pg)
    with caplog.at_level("WARNING"):
        meta = provenance.capture_run_meta(
            FakeClient(raise_knowledge=True), ORG, ANALYZER, tmp_path / "data"
        )
    assert calls == [1]  # the API failure fell through to the Postgres probe
    assert meta["knowledge"] == {"knowledge_sources": None, "epss_rows": None}
    assert any("provenance unavailable" in r.message for r in caplog.records)


def test_capture_survives_missing_analyzer(fake_repo, tmp_path, caplog):
    with caplog.at_level("WARNING"):
        meta = provenance.capture_run_meta(
            FakeClient(analyzer=None), ORG, ANALYZER, tmp_path / "data"
        )
    assert meta["analyzer_steps"] is None
    assert any("not found for read-back" in r.message for r in caplog.records)


# ---- _knowledge_via_postgres --------------------------------------------------


def _fake_pg8000(monkeypatch, rows_by_database):
    """Install a fake pg8000.dbapi in sys.modules (the module is imported lazily
    inside _knowledge_via_postgres) and return the list of executed SQL."""
    executed = []

    class FakeCursor:
        def __init__(self, row):
            self._row = row

        def execute(self, sql):
            executed.append(sql)

        def fetchone(self):
            return self._row

    class FakeConn:
        def __init__(self, row):
            self._row = row

        def cursor(self):
            return FakeCursor(self._row)

        def close(self):
            pass

    def connect(*, user, password, host, port, database, timeout):
        return FakeConn(rows_by_database[database])

    dbapi = SimpleNamespace(connect=connect)
    monkeypatch.setitem(sys.modules, "pg8000", SimpleNamespace(dbapi=dbapi))
    monkeypatch.setitem(sys.modules, "pg8000.dbapi", dbapi)
    return executed


def test_postgres_fallback_selects_and_reports_osv_last(monkeypatch):
    from datetime import datetime, timezone

    executed = _fake_pg8000(
        monkeypatch,
        {
            "config": (
                datetime(2026, 7, 1, tzinfo=timezone.utc),
                "2026-07-02",
                datetime(2026, 7, 3, tzinfo=timezone.utc),
                datetime(2026, 8, 1, tzinfo=timezone.utc),
            ),
            "knowledge": (42,),
        },
    )

    out = provenance._knowledge_via_postgres()

    assert out == {
        "knowledge_sources": {
            "nvd": "2026-07-01T00:00:00+00:00",
            "npm": "2026-07-02",
            "gcve": "2026-07-03T00:00:00+00:00",
            "osv": "2026-08-01T00:00:00+00:00",
        },
        "epss_rows": 42,
    }
    config_sql = [sql for sql in executed if "FROM config" in sql]
    assert len(config_sql) == 1 and "osv_last" in config_sql[0]


def test_postgres_fallback_missing_config_row_yields_nulls(monkeypatch):
    _fake_pg8000(monkeypatch, {"config": None, "knowledge": (7,)})

    out = provenance._knowledge_via_postgres()

    assert out == {
        "knowledge_sources": {"nvd": None, "npm": None, "gcve": None, "osv": None},
        "epss_rows": 7,
    }


# ---- _git helpers -------------------------------------------------------------


def test_git_helpers_nonexistent_repo_return_none(tmp_path):
    missing = tmp_path / "definitely-not-a-repo"
    assert provenance._git_sha(missing) is None
    assert provenance._git_dirty(missing) is None


def test_git_helper_survives_missing_git_binary(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("git: command not found")

    monkeypatch.setattr(provenance.subprocess, "run", boom)
    assert provenance._git(Path("/"), "rev-parse", "HEAD") is None
    assert provenance._git_dirty(Path("/")) is None
