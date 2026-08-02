"""Unit tests for the scheduling / polling orchestrator.

No network and no real clock: the API is a duck-typed fake, GitHub resolution is
monkeypatched at the orchestrator's import site, and poll_and_collect runs on a
fake time module whose sleep() advances it. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import orchestrator  # noqa: E402
from js_vuln_study.client import CodeClarityError  # noqa: E402
from js_vuln_study.sample import ProjectSpec  # noqa: E402
from js_vuln_study.snapshots import Snapshot  # noqa: E402

SHA = "a" * 40
COMMITTED = "2026-07-01T00:00:00Z"


def _spec(name: str = "pkg", url: str = "https://github.com/o/r") -> ProjectSpec:
    return ProjectSpec(
        npm_name=name, rank=1, tier="top-100", git_url=url,
        github_owner="o", github_repo="r", default_branch="main",
    )


def _mrow(status: str = "submitted", **over) -> dict:
    rec = {
        "npm_name": "pkg", "tier": "top-100", "rank": 1,
        "git_url": "https://github.com/o/r", "branch": "main",
        "snapshot_date": "HEAD", "commit_hash": SHA, "committed_at": COMMITTED,
        "project_id": "p1", "analysis_id": "an-0", "status": status, "error": None,
    }
    rec.update(over)
    return rec


def _write_manifest(data_dir: Path, rows: list[dict]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    with (data_dir / "manifest.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _read_manifest(data_dir: Path) -> list[dict]:
    return [
        json.loads(l)
        for l in (data_dir / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]


class FakeClient:
    """Duck-typed stand-in for CodeClarityClient — records calls, plays scripts."""

    def __init__(self) -> None:
        self.imported: list[str] = []
        self.submitted: list[dict] = []
        self.fail_submit = False
        self.fail_import = False
        self.scripts: dict[str, list[dict]] = {}  # analysis_id -> status sequence
        self.results: dict[tuple[str, str], dict] = {}  # (analysis_id, plugin) -> blob
        self.poll_error: Exception | None = None

    def import_project(self, org_id, url, name, description, integration_id=None):
        if self.fail_import:
            raise CodeClarityError("import boom")
        self.imported.append(url)
        return f"proj-{len(self.imported)}"

    def start_analysis(self, org_id, project_id, analyzer_id, branch, commit_hash=None, config=None):
        if self.fail_submit:
            raise CodeClarityError("submit boom")
        self.submitted.append({
            "project_id": project_id, "branch": branch, "commit_hash": commit_hash,
        })
        return f"an-{len(self.submitted)}"

    def get_analysis(self, org_id, project_id, analysis_id):
        if self.poll_error is not None:
            raise self.poll_error
        script = self.scripts[analysis_id]
        return script.pop(0) if len(script) > 1 else script[0]

    def get_result(self, org_id, project_id, analysis_id, plugin_type):
        try:
            return self.results[(analysis_id, plugin_type)]
        except KeyError:
            raise CodeClarityError(f"no {plugin_type} result") from None


@pytest.fixture
def client() -> FakeClient:
    return FakeClient()


@pytest.fixture
def resolved_head(monkeypatch):
    """resolve_snapshots -> HEAD-only grid; resolve_head -> a pinned sha."""
    monkeypatch.setattr(
        orchestrator, "resolve_snapshots",
        lambda owner, repo, dates=(), include_head=True: (
            "main", [Snapshot(date="HEAD", commit_hash=None, committed_at=None)],
        ),
    )
    calls = []

    def fake_resolve_head(owner, repo, branch):
        calls.append((owner, repo, branch))
        return SHA, COMMITTED

    monkeypatch.setattr(orchestrator, "resolve_head", fake_resolve_head)
    return calls


# ---- import_and_schedule ----------------------------------------------------


def test_import_and_schedule_submits_pinned_head(client, resolved_head, tmp_path):
    pending = orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    assert client.imported == ["https://github.com/o/r"]
    assert client.submitted == [
        {"project_id": "proj-1", "branch": "main", "commit_hash": SHA},
    ]
    rows = _read_manifest(tmp_path)
    assert len(rows) == len(pending) == 1
    assert rows[0]["status"] == "submitted"
    assert rows[0]["analysis_id"] == "an-1"
    assert rows[0]["snapshot_date"] == "HEAD"  # grouping key stays HEAD
    assert rows[0]["commit_hash"] == SHA  # …but the submission is pinned
    assert rows[0]["committed_at"] == COMMITTED


def test_import_and_schedule_skips_pairs_already_in_manifest(client, resolved_head, tmp_path):
    _write_manifest(tmp_path, [_mrow(status="completed")])
    pending = orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    assert pending == []
    assert client.submitted == []
    assert client.imported == []  # project_id also reused from the manifest
    assert len(_read_manifest(tmp_path)) == 1


def test_import_and_schedule_reuses_project_id_for_same_git_url(client, resolved_head, tmp_path):
    _write_manifest(tmp_path, [_mrow(status="completed", snapshot_date="2024-01-01")])
    orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    assert client.imported == []
    assert client.submitted[0]["project_id"] == "p1"


def test_import_and_schedule_records_skip_on_resolution_failure(client, monkeypatch, tmp_path):
    def boom(owner, repo, dates=(), include_head=True):
        raise RuntimeError("github down")

    monkeypatch.setattr(orchestrator, "resolve_snapshots", boom)
    pending = orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    assert pending == []
    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "skipped"
    assert row["snapshot_date"] == "*"
    assert row["project_id"] is None
    assert row["error"].startswith("snapshot-resolution:")


def test_import_and_schedule_records_skip_when_no_branch(client, monkeypatch, tmp_path):
    monkeypatch.setattr(
        orchestrator, "resolve_snapshots",
        lambda owner, repo, dates=(), include_head=True: (None, []),
    )
    orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "skipped"
    assert row["error"] == "no default branch / no snapshots"


def test_import_and_schedule_records_skip_on_import_failure(client, resolved_head, tmp_path):
    client.fail_import = True
    orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "skipped"
    assert row["error"].startswith("import:")


def test_import_and_schedule_records_failed_submit(client, resolved_head, tmp_path):
    client.fail_submit = True
    pending = orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "failed-submit"
    assert row["analysis_id"] is None
    assert "submit boom" in row["error"]
    assert len(pending) == 1  # failed-submit rows are returned too


# ---- _pin_head ---------------------------------------------------------------


def test_pin_head_pins_to_resolved_sha(resolved_head):
    snap = Snapshot(date="HEAD", commit_hash=None, committed_at=None)
    out = orchestrator._pin_head(_spec(), "main", snap)
    assert out == Snapshot(date="HEAD", commit_hash=SHA, committed_at=COMMITTED)
    assert resolved_head == [("o", "r", "main")]


def test_pin_head_degrades_to_unpinned_when_unresolved(monkeypatch, caplog):
    monkeypatch.setattr(orchestrator, "resolve_head", lambda *a: None)
    snap = Snapshot(date="HEAD", commit_hash=None, committed_at=None)
    with caplog.at_level("WARNING"):
        assert orchestrator._pin_head(_spec(), "main", snap) is snap
    assert any("submitting unpinned" in r.message for r in caplog.records)


def test_pin_head_degrades_to_unpinned_when_resolve_raises(monkeypatch, caplog):
    def boom(*a):
        raise RuntimeError("rate limited")

    monkeypatch.setattr(orchestrator, "resolve_head", boom)
    snap = Snapshot(date="HEAD", commit_hash=None, committed_at=None)
    with caplog.at_level("WARNING"):
        assert orchestrator._pin_head(_spec(), "main", snap) is snap
    assert any("HEAD resolution errored" in r.message for r in caplog.records)


def test_head_with_known_commit_is_not_repinned(client, monkeypatch, tmp_path, resolved_head):
    monkeypatch.setattr(
        orchestrator, "resolve_snapshots",
        lambda owner, repo, dates=(), include_head=True: (
            "main", [Snapshot(date="HEAD", commit_hash="b" * 40, committed_at=COMMITTED)],
        ),
    )
    orchestrator.import_and_schedule(
        client, "org", "anlz", [_spec()], tmp_path, skip_head_only=True,
    )
    assert resolved_head == []  # resolve_head never consulted
    assert client.submitted[0]["commit_hash"] == "b" * 40


# ---- _record_skip -------------------------------------------------------------


def test_record_skip_row_shape(tmp_path):
    rec = orchestrator._record_skip(tmp_path, _spec(), "*", "why not")
    (row,) = _read_manifest(tmp_path)
    assert row == {
        "npm_name": "pkg", "tier": "top-100", "rank": 1,
        "git_url": "https://github.com/o/r", "branch": None,
        "snapshot_date": "*", "commit_hash": None, "committed_at": None,
        "project_id": None, "analysis_id": None,
        "status": "skipped", "error": "why not",
    }
    assert rec.status == "skipped"


# ---- retry_failed --------------------------------------------------------------


def _retry_manifest(tmp_path) -> list[dict]:
    rows = [
        _mrow(status="failed", npm_name="a", analysis_id="an-old", error="stall"),
        _mrow(status="failure", npm_name="b", snapshot_date="2024-01-01",
              commit_hash="b" * 40, error="download"),
        _mrow(status="completed", npm_name="c"),
        _mrow(status="skipped", npm_name="d", project_id=None, branch=None,
              analysis_id=None, error="import"),
        _mrow(status="failed-submit", npm_name="e", analysis_id=None, error="500"),
    ]
    _write_manifest(tmp_path, rows)
    return rows


def test_retry_dry_run_submits_nothing(client, tmp_path):
    before = _retry_manifest(tmp_path)
    out = orchestrator.retry_failed(client, "org", "anlz", tmp_path, dry_run=True)
    assert out == []
    assert client.submitted == []
    assert _read_manifest(tmp_path) == before


def test_retry_replaces_rows_in_place(client, tmp_path):
    _retry_manifest(tmp_path)
    out = orchestrator.retry_failed(client, "org", "anlz", tmp_path)
    assert len(out) == 3  # failed + failure + failed-submit; skipped/completed excluded
    rows = _read_manifest(tmp_path)
    assert len(rows) == 5  # replaced, never appended
    assert [r["npm_name"] for r in rows] == ["a", "b", "c", "d", "e"]
    row_a = rows[0]
    assert row_a["status"] == "submitted"
    assert row_a["analysis_id"] == "an-1"  # fresh id
    assert row_a["error"] is None
    assert row_a["commit_hash"] == SHA  # a pinned row stays pinned to its commit
    assert rows[2]["status"] == "completed"  # untouched
    assert rows[3]["status"] == "skipped"


def test_retry_skips_rows_without_project_or_branch(client, tmp_path, caplog):
    _write_manifest(tmp_path, [
        _mrow(status="skipped", project_id=None, branch=None, analysis_id=None),
    ])
    with caplog.at_level("WARNING"):
        out = orchestrator.retry_failed(client, "org", "anlz", tmp_path, statuses={"skipped"})
    assert out == []
    assert client.submitted == []
    assert any("no project_id/branch" in r.message for r in caplog.records)


def test_retry_status_filter(client, tmp_path):
    _retry_manifest(tmp_path)
    out = orchestrator.retry_failed(client, "org", "anlz", tmp_path, statuses={"failed"})
    assert [r.npm_name for r in out] == ["a"]


def test_retry_date_filter(client, tmp_path):
    _retry_manifest(tmp_path)
    out = orchestrator.retry_failed(client, "org", "anlz", tmp_path, date="2024-01-01")
    assert [r.npm_name for r in out] == ["b"]
    assert client.submitted[0]["commit_hash"] == "b" * 40


def test_retry_project_filter(client, tmp_path):
    _retry_manifest(tmp_path)
    out = orchestrator.retry_failed(client, "org", "anlz", tmp_path, project="e")
    assert [r.npm_name for r in out] == ["e"]


def test_retry_without_manifest_warns(client, tmp_path, caplog):
    with caplog.at_level("WARNING"):
        assert orchestrator.retry_failed(client, "org", "anlz", tmp_path) == []
    assert any("no manifest" in r.message for r in caplog.records)


# ---- poll_and_collect ------------------------------------------------------------


class FakeTime:
    """Deterministic clock: only sleep() advances it."""

    def __init__(self) -> None:
        self.now = 1_000_000.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def poll_env(monkeypatch):
    """Fake clock + unit jitter + counted reclaim, wired into the orchestrator."""
    clock = FakeTime()
    monkeypatch.setattr(orchestrator, "time", clock)
    monkeypatch.setattr(orchestrator, "random", SimpleNamespace(uniform=lambda a, b: 1.0))
    monkeypatch.setattr(orchestrator, "POLL_TIMEOUT", 50)
    monkeypatch.setattr(orchestrator, "STARTED_TIMEOUT", 200)
    reclaims: list[tuple[str, str]] = []
    monkeypatch.setattr(
        orchestrator, "reclaim_leaf",
        lambda org, project_id, leaf: reclaims.append((project_id, leaf)) or 1_000_000,
    )
    return SimpleNamespace(clock=clock, reclaims=reclaims, monkeypatch=monkeypatch)


ONGOING = {"status": "ongoing", "steps": [[{"name": "js-sbom", "status": "started"}]]}
QUEUED = {"status": "started", "steps": []}


def test_poll_happy_terminal_persists_blobs_and_reclaims_once(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    client.scripts["an-1"] = [QUEUED, {"status": "completed", "steps": []}]
    for plugin in orchestrator.PLUGIN_TYPES:
        client.results[("an-1", plugin)] = {"workspaces": {".": {}}, "plugin": plugin}

    orchestrator.poll_and_collect(client, "org", tmp_path)

    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "completed"
    assert row["error"] is None
    out = tmp_path / "raw" / "p1" / "an-1"
    for plugin in orchestrator.PLUGIN_TYPES:
        blob = json.loads((out / f"{plugin}.json").read_text())
        assert blob["plugin"] == plugin
    assert poll_env.reclaims == [("p1", SHA)]  # exactly once, commit leaf


def test_poll_shared_leaf_reclaimed_only_after_last_record(client, poll_env, tmp_path):
    # Two analyses on the same (project, branch) leaf — an unpinned HEAD pair.
    _write_manifest(tmp_path, [
        _mrow(analysis_id="an-1", commit_hash=None),
        _mrow(analysis_id="an-2", commit_hash=None, snapshot_date="2024-01-01"),
    ])
    client.scripts["an-1"] = [{"status": "completed", "steps": []}]
    client.scripts["an-2"] = [ONGOING, {"status": "completed", "steps": []}]

    orchestrator.poll_and_collect(client, "org", tmp_path)

    assert [r["status"] for r in _read_manifest(tmp_path)] == ["completed", "completed"]
    assert poll_env.reclaims == [("p1", "main")]  # held until the second finished


def test_poll_missing_result_blob_is_tolerated(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    client.scripts["an-1"] = [{"status": "completed", "steps": []}]
    client.results[("an-1", "js-sbom")] = {"workspaces": {}}
    # vuln-finder / license-finder blobs missing -> get_result raises

    orchestrator.poll_and_collect(client, "org", tmp_path)

    out = tmp_path / "raw" / "p1" / "an-1"
    assert (out / "js-sbom.json").exists()
    assert not (out / "vuln-finder.json").exists()
    assert _read_manifest(tmp_path)[0]["status"] == "completed"


def test_poll_stall_timeout_fails_frozen_running_analysis(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    client.scripts["an-1"] = [ONGOING]  # running, but the signature never moves

    orchestrator.poll_and_collect(client, "org", tmp_path)

    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "failed"
    assert row["error"].startswith("ongoing stall: no progress for")
    # a client-side timeout must NOT reclaim — the server may still be writing
    assert poll_env.reclaims == []


def test_poll_progress_signature_change_resets_stall_clock(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    # A step transition on every poll, completing only after the cumulative wait
    # has far exceeded POLL_TIMEOUT — survives solely because the clock resets.
    moving = [
        {"status": "ongoing", "steps": [[{"name": "js-sbom", "status": f"s{i}"}]]}
        for i in range(6)
    ]
    client.scripts["an-1"] = moving + [{"status": "completed", "steps": []}]
    start = poll_env.clock.now

    orchestrator.poll_and_collect(client, "org", tmp_path)

    assert _read_manifest(tmp_path)[0]["status"] == "completed"
    assert poll_env.clock.now - start > orchestrator.POLL_TIMEOUT  # stall window overrun


def test_poll_queued_only_row_survives_stall_and_dies_at_ceiling(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    client.scripts["an-1"] = [QUEUED]  # never picked up by the downloader
    start = poll_env.clock.now

    orchestrator.poll_and_collect(client, "org", tmp_path)

    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "failed"
    assert row["error"] == "queued > started ceiling"  # ceiling, not the stall path
    elapsed = poll_env.clock.now - start
    assert elapsed > orchestrator.STARTED_TIMEOUT  # outlived the stall window (50s)
    assert poll_env.reclaims == []


def test_poll_transient_get_analysis_errors_fail_only_past_ceiling(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    client.poll_error = CodeClarityError("502 bad gateway")

    orchestrator.poll_and_collect(client, "org", tmp_path)

    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "failed"
    assert row["error"].startswith("poll error past started ceiling:")


def test_poll_sad_terminal_records_failure_reason_and_reclaims(client, poll_env, tmp_path):
    _write_manifest(tmp_path, [_mrow(analysis_id="an-1")])
    client.scripts["an-1"] = [
        {"status": "failure", "failure_reason": "could not resolve commit", "steps": []},
    ]

    orchestrator.poll_and_collect(client, "org", tmp_path)

    (row,) = _read_manifest(tmp_path)
    assert row["status"] == "failure"
    assert row["error"] == "could not resolve commit"
    assert poll_env.reclaims == [("p1", SHA)]  # sad-terminal clones are reclaimed too


def test_poll_rewrites_manifest_after_each_transition(client, poll_env, tmp_path, monkeypatch):
    _write_manifest(tmp_path, [
        _mrow(analysis_id="an-1"),
        _mrow(analysis_id="an-2", snapshot_date="2024-01-01", commit_hash="b" * 40),
    ])
    client.scripts["an-1"] = [{"status": "completed", "steps": []}]
    client.scripts["an-2"] = [ONGOING, {"status": "completed", "steps": []}]

    real_rewrite = orchestrator._rewrite_manifest
    calls: list[list[str]] = []

    def counting_rewrite(path, records):
        real_rewrite(path, records)
        calls.append([r["status"] for r in records])

    monkeypatch.setattr(orchestrator, "_rewrite_manifest", counting_rewrite)
    orchestrator.poll_and_collect(client, "org", tmp_path)

    # one flush per terminal transition, plus the final rewrite
    assert len(calls) == 3
    assert calls[0] == ["completed", "submitted"]  # first transition flushed in place
    assert calls[-1] == ["completed", "completed"]


def test_poll_without_manifest_warns_and_returns(client, tmp_path, caplog):
    with caplog.at_level("WARNING"):
        orchestrator.poll_and_collect(client, "org", tmp_path)
    assert any("no manifest" in r.message for r in caplog.records)


# ---- _is_running / _progress_sig -------------------------------------------------


@pytest.mark.parametrize("analysis,running", [
    ({"status": "started", "steps": []}, False),
    ({"status": "queued", "steps": []}, False),
    ({"status": "", "steps": []}, False),
    ({"status": None}, False),
    ({"status": "ongoing", "steps": []}, True),
    ({"status": "started", "steps": [[{"name": "js-sbom", "status": "started"}]]}, True),
    ({"status": "started", "steps": [[{"name": "js-sbom", "status": ""}]]}, False),
])
def test_is_running(analysis, running):
    assert orchestrator._is_running(analysis) is running


def test_progress_sig_tracks_step_level_movement():
    a = {"status": "ongoing", "steps": [[{"name": "js-sbom", "status": "started"}]]}
    b = {"status": "ongoing", "steps": [[{"name": "js-sbom", "status": "success"}]]}
    assert orchestrator._progress_sig(a) != orchestrator._progress_sig(b)
    assert orchestrator._progress_sig(a) == orchestrator._progress_sig(dict(a))
    assert orchestrator._progress_sig({"status": "started"}) == ("started", ())


# ---- _failure_reason ---------------------------------------------------------------


def test_failure_reason_prefers_api_failure_reason(client):
    analysis = {"failure_reason": "downloader: sha not found", "steps": []}
    out = orchestrator._failure_reason(client, "org", _mrow(analysis_id="an-1"), analysis)
    assert out == "downloader: sha not found"


def test_failure_reason_reads_failing_step_blob(client):
    client.results[("an-1", "js-sbom")] = {
        "analysis_info": {"errors": [
            {"public_error": {"key": "UnableToClone", "description": "auth failed"}},
        ]},
    }
    analysis = {"steps": [[{"name": "js-sbom", "status": "failure"}]]}
    out = orchestrator._failure_reason(client, "org", _mrow(analysis_id="an-1"), analysis)
    assert out == "js-sbom: UnableToClone: auth failed"


def test_failure_reason_falls_back_when_no_blob(client):
    analysis = {"steps": [[{"name": "vuln-finder", "status": "failure"}]]}
    out = orchestrator._failure_reason(client, "org", _mrow(analysis_id="an-1"), analysis)
    assert out == "failure at vuln-finder; no plugin result"


def test_failure_reason_stage_zero_when_no_steps(client):
    out = orchestrator._failure_reason(client, "org", _mrow(analysis_id="an-1"), {"steps": []})
    assert out == "failure at stage-0/download; no plugin result"
