"""Unit tests for resubmit_frozen — the ladder rung's commit-pinned submit path.

No network: the API is a duck-typed fake and GitHub resolution is poisoned to
prove it is never consulted (SHAs come from the source manifest). Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import orchestrator  # noqa: E402
from js_vuln_study.client import CodeClarityError  # noqa: E402

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def _srow(url: str = "https://github.com/o/r1", **over) -> dict:
    rec = {
        "npm_name": url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1],
        "tier": "top-100", "rank": 1,
        "git_url": url, "branch": "main",
        "snapshot_date": "2024-01-01", "commit_hash": SHA_A,
        "committed_at": "2024-01-01T00:00:00Z",
        "project_id": "archived-p1", "analysis_id": "archived-an-1",
        "status": "completed", "error": None,
    }
    rec.update(over)
    return rec


def _source_rows() -> list[dict]:
    """Archive-shaped source: two dates pinned to one sha, a pinned HEAD, a
    failure with a sha, an unpinned skip, and an unpinned completed HEAD."""
    return [
        _srow(),
        _srow(snapshot_date="2024-04-01", commit_hash=SHA_A),  # same tree as row 0
        _srow(snapshot_date="HEAD", commit_hash=SHA_B),
        _srow(url="https://github.com/o/r2", status="failure",
              commit_hash=SHA_C, error="worker crash"),
        _srow(url="https://github.com/o/r3", status="skipped", snapshot_date="*",
              commit_hash=None, branch=None, project_id=None, analysis_id=None,
              error="import: boom"),
        _srow(url="https://github.com/o/r4", snapshot_date="HEAD", commit_hash=None),
    ]


def _write_source(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return path


def _read_manifest(data_dir: Path) -> list[dict]:
    path = data_dir / "manifest.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(l)
        for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]


class FakeClient:
    """Duck-typed CodeClarityClient: records calls, serves a live project list."""

    def __init__(self) -> None:
        self.projects: list[dict] = []
        self.imported: list[str] = []
        self.submitted: list[dict] = []
        self.fail_import = False
        self.list_error: Exception | None = None

    def list_projects(self, org_id):
        if self.list_error is not None:
            raise self.list_error
        return self.projects

    def import_project(self, org_id, url, name, description, integration_id=None):
        if self.fail_import:
            raise CodeClarityError("import boom")
        self.imported.append(url)
        return f"proj-{url.rsplit('/', 1)[-1]}"

    def start_analysis(self, org_id, project_id, analyzer_id, branch, commit_hash=None, config=None):
        self.submitted.append({
            "project_id": project_id, "branch": branch, "commit_hash": commit_hash,
        })
        return f"an-{project_id}-{commit_hash}"


@pytest.fixture
def client() -> FakeClient:
    return FakeClient()


@pytest.fixture(autouse=True)
def no_github(monkeypatch):
    """resubmit-frozen must never resolve anything on GitHub — poison both."""
    def boom(*a, **k):
        raise AssertionError("GitHub resolution must not be consulted")

    monkeypatch.setattr(orchestrator, "resolve_snapshots", boom)
    monkeypatch.setattr(orchestrator, "resolve_head", boom)


@pytest.fixture
def source(tmp_path) -> Path:
    return _write_source(tmp_path / "archive" / "manifest.jsonl", _source_rows())


@pytest.fixture
def rung(tmp_path) -> Path:
    return tmp_path / "rung"


# ---- selection / dedupe ------------------------------------------------------


def test_selects_all_statuses_by_default(client, source, rung):
    pending = orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    # 4 sha-carrying rows submitted (incl. the failure row), 2 sha-less skipped.
    assert [r.status for r in pending] == ["submitted"] * 4
    assert {s["commit_hash"] for s in client.submitted} == {SHA_A, SHA_B, SHA_C}
    rows = _read_manifest(rung)
    assert len(rows) == 6
    by_key = {(r["git_url"], r["snapshot_date"]): r for r in rows}
    assert by_key[("https://github.com/o/r2", "2024-01-01")]["status"] == "submitted"


def test_only_completed_excludes_sad_rows(client, source, rung):
    pending = orchestrator.resubmit_frozen(
        client, "org", "anlz", source, rung, only_completed=True,
    )
    assert len(pending) == 3  # the r2 failure row is out
    assert all(s["commit_hash"] != SHA_C for s in client.submitted)
    # the source 'skipped' row is also out; only r4's unpinned HEAD skips
    skips = [r for r in _read_manifest(rung) if r["status"] == "skipped"]
    assert [r["git_url"] for r in skips] == ["https://github.com/o/r4"]


def test_dedupe_sha_keeps_first_row_per_tree(client, source, rung):
    orchestrator.resubmit_frozen(
        client, "org", "anlz", source, rung, only_completed=True, dedupe_sha=True,
    )
    sub_rows = [r for r in _read_manifest(rung) if r["status"] == "submitted"]
    # SHA_A submitted once, under the FIRST row's snapshot_date.
    assert [(r["snapshot_date"], r["commit_hash"]) for r in sub_rows] == [
        ("2024-01-01", SHA_A), ("HEAD", SHA_B),
    ]
    assert len(client.submitted) == 2


def test_missing_sha_recorded_as_skip(client, source, rung):
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    skips = {r["git_url"]: r for r in _read_manifest(rung) if r["status"] == "skipped"}
    assert set(skips) == {"https://github.com/o/r3", "https://github.com/o/r4"}
    assert skips["https://github.com/o/r3"]["error"] == "no pinned commit in source"
    assert skips["https://github.com/o/r3"]["snapshot_date"] == "*"  # verbatim
    assert skips["https://github.com/o/r4"]["snapshot_date"] == "HEAD"


# ---- commit-pinned submission ------------------------------------------------


def test_head_rows_submit_at_archived_sha_not_reresolved(client, source, rung):
    # no_github (autouse) raises on any resolver call — reaching here proves
    # the resolution step is skipped entirely.
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung, only_completed=True)
    head_rows = [r for r in _read_manifest(rung) if r["snapshot_date"] == "HEAD" and r["status"] == "submitted"]
    (row,) = head_rows
    assert row["commit_hash"] == SHA_B  # the archived SHA, snapshot_date verbatim
    assert row["submitted_at"]  # telemetry stamped
    assert {"project_id": "proj-r1", "branch": "main", "commit_hash": SHA_B} in client.submitted


def test_committed_at_carried_over(client, source, rung):
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung, only_completed=True)
    row = _read_manifest(rung)[0]
    assert row["committed_at"] == "2024-01-01T00:00:00Z"


# ---- read-only source / idempotency / dry-run --------------------------------


def test_source_manifest_is_read_only(client, source, rung):
    before = source.read_bytes()
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    assert source.read_bytes() == before
    assert sorted(p.name for p in source.parent.iterdir()) == ["manifest.jsonl"]


def test_rerun_is_idempotent_per_rung(client, source, rung):
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    first = _read_manifest(rung)
    n_submits = len(client.submitted)
    pending = orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    assert pending == []
    assert len(client.submitted) == n_submits  # nothing re-POSTed
    assert _read_manifest(rung) == first  # nothing re-appended (skips included)


def test_dry_run_writes_nothing_and_needs_no_client(source, rung, caplog):
    with caplog.at_level("INFO"):
        pending = orchestrator.resubmit_frozen(
            None, "", "", source, rung,
            only_completed=True, dedupe_sha=True, dry_run=True,
        )
    assert pending == []
    assert not rung.exists()  # not even the directory
    assert any("[dry-run] resubmit-frozen" in r.message for r in caplog.records)


def test_missing_source_warns_and_returns(client, rung, tmp_path, caplog):
    with caplog.at_level("WARNING"):
        out = orchestrator.resubmit_frozen(
            client, "org", "anlz", tmp_path / "nope.jsonl", rung,
        )
    assert out == []
    assert any("no source manifest" in r.message for r in caplog.records)


# ---- project mapping ---------------------------------------------------------


def test_stale_projects_reimported_by_git_url(client, source, rung):
    # Server has nothing (post-`clean` state): every archived project_id is
    # stale, so each distinct git_url with a submission is imported once.
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung, only_completed=True)
    assert sorted(client.imported) == ["https://github.com/o/r1"]
    assert all(s["project_id"] == "proj-r1" for s in client.submitted)


def test_live_projects_reused_without_import(client, source, rung):
    client.projects = [
        {"id": "live-r1", "url": "https://github.com/o/r1"},
        {"id": "live-r2", "url": "https://github.com/o/r2"},
    ]
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    assert client.imported == []
    assert {s["project_id"] for s in client.submitted} == {"live-r1", "live-r2"}


def test_list_projects_failure_falls_back_to_rung_manifest_ids(client, source, rung, caplog):
    # A prior rung pass recorded a project id; listing then breaking must not
    # trigger a re-import for that url.
    rung.mkdir(parents=True)
    seeded = _srow(snapshot_date="2022-01-01", commit_hash="d" * 40,
                   project_id="rung-p1", analysis_id="rung-an-0")
    (rung / "manifest.jsonl").write_text(json.dumps(seeded) + "\n", encoding="utf-8")
    client.list_error = CodeClarityError("500")
    with caplog.at_level("WARNING"):
        orchestrator.resubmit_frozen(client, "org", "anlz", source, rung, only_completed=True)
    assert any("could not list projects" in r.message for r in caplog.records)
    assert client.imported == []
    assert all(s["project_id"] == "rung-p1" for s in client.submitted)


def test_import_failure_records_project_wide_skip(client, source, rung):
    client.fail_import = True
    pending = orchestrator.resubmit_frozen(
        client, "org", "anlz", source, rung, only_completed=True,
    )
    assert pending == []
    rows = _read_manifest(rung)
    import_skips = [r for r in rows if (r["error"] or "").startswith("import:")]
    # one "*" skip per project (r1), not one per selected row
    assert [(r["git_url"], r["snapshot_date"]) for r in import_skips] == [
        ("https://github.com/o/r1", "*"),
    ]


# ---- denylist ----------------------------------------------------------------


def test_rung_denylist_converts_to_skip(client, source, rung):
    orchestrator.record_unresolvable(
        rung,
        {"git_url": "https://github.com/o/r2", "snapshot_date": "2024-01-01",
         "commit_hash": SHA_C},
        "CommitUnresolvable: gone",
    )
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    assert all(s["commit_hash"] != SHA_C for s in client.submitted)
    by_key = {(r["git_url"], r["snapshot_date"]): r for r in _read_manifest(rung)}
    row = by_key[("https://github.com/o/r2", "2024-01-01")]
    assert row["status"] == "skipped"
    assert row["error"] == "denylist: CommitUnresolvable: gone"


def test_source_dir_denylist_also_consulted(client, source, rung):
    orchestrator.record_unresolvable(
        source.parent,
        {"git_url": "https://github.com/o/r2", "snapshot_date": "2024-01-01",
         "commit_hash": SHA_C},
        "CommitUnresolvable: gone",
    )
    orchestrator.resubmit_frozen(client, "org", "anlz", source, rung)
    assert all(s["commit_hash"] != SHA_C for s in client.submitted)


def test_ignore_denylist_submits_anyway(client, source, rung):
    orchestrator.record_unresolvable(
        rung,
        {"git_url": "https://github.com/o/r2", "snapshot_date": "2024-01-01",
         "commit_hash": SHA_C},
        "CommitUnresolvable: gone",
    )
    orchestrator.resubmit_frozen(
        client, "org", "anlz", source, rung, ignore_denylist=True,
    )
    assert any(s["commit_hash"] == SHA_C for s in client.submitted)


# ---- parallel determinism ----------------------------------------------------


def test_parallel_matches_serial_manifest(source, tmp_path):
    manifests = {}
    for workers in (1, 8):
        rung = tmp_path / f"w{workers}"
        client = FakeClient()
        orchestrator.resubmit_frozen(
            client, "org", "anlz", source, rung, max_workers=workers,
        )
        manifests[workers] = [
            {k: v for k, v in r.items() if k != "submitted_at"}
            for r in _read_manifest(rung)
        ]
    assert manifests[8] == manifests[1]
