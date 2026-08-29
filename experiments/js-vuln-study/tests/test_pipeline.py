from __future__ import annotations

import httpx
import pytest

from js_vuln_study import github, manifest, pipeline
from js_vuln_study.client import CodeClarityError
from js_vuln_study.config import Settings
from js_vuln_study.sample import ProjectSpec

from conftest import row


def fake_github_client(repos: dict) -> httpx.Client:
    """`repos` maps (owner, repo) -> {"default_branch": str, "commits": {until_or_None: (sha, date) | None}}."""

    def handler(request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "repos":
            meta = repos.get((parts[1], parts[2]))
            if meta is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"default_branch": meta["default_branch"]})
        if len(parts) == 4 and parts[0] == "repos" and parts[3] == "commits":
            meta = repos.get((parts[1], parts[2]))
            if meta is None:
                return httpx.Response(404)
            until = request.url.params.get("until")
            result = meta["commits"].get(until, "MISS")
            if result == "MISS":
                return httpx.Response(200, json=[])
            if result is None:
                return httpx.Response(200, json=[])
            sha, date = result
            return httpx.Response(200, json=[{"sha": sha, "commit": {"committer": {"date": date}}}])
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler), base_url=github.GITHUB_API)


REPOS = {
    ("acme", "widgets"): {
        "default_branch": "main",
        "commits": {
            None: ("headsha" + "0" * 33, "2026-08-01T00:00:00Z"),
            "2024-01-01T00:00:00+00:00": ("datedsha" + "0" * 32, "2023-12-31T00:00:00Z"),
        },
    },
}
SETTINGS = Settings(cc_base_url="https://x", cc_email="e", cc_password="p", github_token="tok")
SPEC = ProjectSpec(
    npm_name="acme/widgets", rank=0, tier="top100",
    git_url="https://github.com/acme/widgets", github_owner="acme", github_repo="widgets",
    default_branch="main",
)


def _patch_github(monkeypatch, repos):
    monkeypatch.setattr(pipeline.github, "make_client", lambda *a, **k: fake_github_client(repos))


# ---- submit_missing ---------------------------------------------------------


def test_submit_missing_pins_head_and_dated_snapshots(monkeypatch, fake_api):
    _patch_github(monkeypatch, REPOS)
    rows = pipeline.submit_missing(
        fake_api, _study_stub(["2024-01-01"]), SETTINGS, "org", "analyzer", "integ",
        [SPEC], set(), {}, "run1",
    )
    by_date = {r.snapshot_date: r for r in rows}
    assert by_date["HEAD"].commit_hash == "headsha" + "0" * 33
    assert by_date["HEAD"].state == "pending"
    assert by_date["2024-01-01"].commit_hash == "datedsha" + "0" * 32
    assert all(r.run_id == "run1" for r in rows)


def _study_stub(grid, snapshots=True, knowledge_asof=None):
    class S:
        pass

    s = S()
    s.grid = grid
    s.snapshots = snapshots
    s.knowledge_asof = knowledge_asof
    s.name = "t"
    return s


def test_submit_missing_zero_github_calls_when_fully_covered(monkeypatch, fake_api):
    calls = []

    def make_client(*a, **k):
        def handler(request):
            calls.append(request.url.path)
            return httpx.Response(200, json={})

        return httpx.Client(transport=httpx.MockTransport(handler), base_url=github.GITHUB_API)

    monkeypatch.setattr(pipeline.github, "make_client", make_client)
    existing = {("https://github.com/acme/widgets", "HEAD"), ("https://github.com/acme/widgets", "2024-01-01")}
    out = pipeline.submit_missing(
        fake_api, _study_stub(["2024-01-01"]), SETTINGS, "org", "analyzer", "integ",
        [SPEC], existing, {}, "run1",
    )
    assert out == []
    assert calls == []


def test_submit_missing_project_id_reused_per_git_url(monkeypatch, fake_api):
    _patch_github(monkeypatch, REPOS)
    project_ids: dict = {}
    pipeline.submit_missing(fake_api, _study_stub([]), SETTINGS, "org", "az", "integ", [SPEC], set(), project_ids, "r")
    assert len(fake_api.import_calls) == 1
    pipeline.submit_missing(fake_api, _study_stub([]), SETTINGS, "org", "az", "integ", [SPEC], set(), project_ids, "r")
    # HEAD already in project_ids' git_url mapping but not in existing_keys, so
    # it resubmits HEAD (a fresh submit_missing call has no existing_keys) yet
    # must not re-import the project a second time.
    assert len(fake_api.import_calls) == 1


def test_submit_missing_knowledge_asof_on_row_and_config(monkeypatch, fake_api):
    _patch_github(monkeypatch, REPOS)
    rows = pipeline.submit_missing(
        fake_api, _study_stub([], knowledge_asof="2026-08-03"), SETTINGS, "org", "az", "integ",
        [SPEC], set(), {}, "r",
    )
    head = next(r for r in rows if r.snapshot_date == "HEAD")
    assert head.knowledge_asof == "2026-08-03"
    call = next(c for c in fake_api.start_calls if c["project_id"] == head.project_id)
    assert call["config"]["vuln-finder"]["knowledge_asof"] == "2026-08-03"


def test_submit_missing_post_failure_is_failed_row(monkeypatch, fake_api):
    _patch_github(monkeypatch, REPOS)

    def boom(*a, **k):
        raise CodeClarityError("500 server error")

    monkeypatch.setattr(fake_api, "start_analysis", boom)
    rows = pipeline.submit_missing(fake_api, _study_stub([]), SETTINGS, "org", "az", "integ", [SPEC], set(), {}, "r")
    head = next(r for r in rows if r.snapshot_date == "HEAD")
    assert head.state == "failed"
    assert head.analysis_id is None
    assert head.error.startswith("submit:")


def test_submit_missing_head_failure_is_single_skipped_row_not_project_wide(monkeypatch, fake_api):
    repos = {("acme", "widgets"): {"default_branch": "main", "commits": {None: None, "2024-01-01T00:00:00+00:00": ("d" * 40, "2023-12-31T00:00:00Z")}}}
    _patch_github(monkeypatch, repos)
    rows = pipeline.submit_missing(fake_api, _study_stub(["2024-01-01"]), SETTINGS, "org", "az", "integ", [SPEC], set(), {}, "r")
    by_date = {r.snapshot_date: r for r in rows}
    assert by_date["HEAD"].state == "skipped"
    assert "head-resolution" in by_date["HEAD"].error
    assert by_date["2024-01-01"].state == "pending"  # dated snapshot unaffected


def test_submit_missing_repo_not_found_is_project_wide_skip(monkeypatch, fake_api):
    _patch_github(monkeypatch, {})  # empty repos dict -> every lookup 404s
    rows = pipeline.submit_missing(fake_api, _study_stub(["2024-01-01"]), SETTINGS, "org", "az", "integ", [SPEC], set(), {}, "r")
    assert len(rows) == 1
    assert rows[0].snapshot_date == "*"
    assert rows[0].state == "skipped"


# ---- submit_frozen -----------------------------------------------------------


def test_submit_frozen_never_calls_github_dedupes_by_sha(fake_api):
    source = [
        row(git_url="https://github.com/a/a", snapshot_date="2024-01-01", commit_hash="s1" * 20, state="done"),
        row(git_url="https://github.com/a/a", snapshot_date="2024-04-01", commit_hash="s1" * 20, state="done"),  # same sha
        row(git_url="https://github.com/a/a", snapshot_date="2024-07-01", commit_hash="s2" * 20, state="done"),
        row(git_url="https://github.com/a/a", snapshot_date="2024-10-01", commit_hash=None, state="done"),  # no-sha
        row(git_url="https://github.com/a/a", snapshot_date="2025-01-01", commit_hash="s3" * 20, state="failed"),  # not done
    ]
    src_path = _write_source(source)
    out = pipeline.submit_frozen(fake_api, _study_stub([], knowledge_asof="2024-01-01"), "org", "az", "integ", src_path, set(), {}, "rung1")
    submitted_dates = {r.snapshot_date for r in out if r.state == "pending"}
    assert submitted_dates == {"2024-01-01", "2024-07-01"}  # 2024-04-01 collapsed onto the first
    assert len(fake_api.import_calls) == 1  # one project, imported once
    no_sha = next(r for r in out if r.snapshot_date == "2024-10-01")
    assert no_sha.state == "skipped"
    assert no_sha.error == "no pinned commit in source"


def _write_source(rows_):
    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp())
    p = d / "manifest.jsonl"
    manifest.write_all(p, rows_)
    return p


# ---- retry --------------------------------------------------------------------


def test_retry_re_drives_eligible_rows_with_own_knowledge_asof(fake_api, study):
    rows = [row(state="failed", attempts=0, knowledge_asof="2026-08-03", error="failure at stage-0")]
    manifest.write_all(study.manifest_path, rows)
    n = pipeline.retry(fake_api, study, "org", "az")
    assert n == 1
    new_rows = manifest.read(study.manifest_path)
    assert new_rows[0].state == "pending"
    assert new_rows[0].attempts == 1
    call = fake_api.start_calls[-1]
    assert call["config"]["vuln-finder"]["knowledge_asof"] == "2026-08-03"


def test_retry_skips_commit_unresolvable(fake_api, study):
    rows = [row(state="failed", error="CommitUnresolvable: commit x in y: z")]
    manifest.write_all(study.manifest_path, rows)
    n = pipeline.retry(fake_api, study, "org", "az")
    assert n == 0
    assert manifest.read(study.manifest_path)[0].state == "failed"


def test_retry_stops_at_attempts_cap(fake_api, study):
    study.config["study"]["retries"] = 1
    rows = [row(state="failed", attempts=1, error="stall")]
    manifest.write_all(study.manifest_path, rows)
    assert pipeline.retry(fake_api, study, "org", "az") == 0


def test_retry_one_with_force_ignores_attempts_cap_and_marker(fake_api, study):
    study.config["study"]["retries"] = 0
    rows = [row(state="failed", attempts=5, error="CommitUnresolvable: x")]
    manifest.write_all(study.manifest_path, rows)
    n = pipeline.retry_one(fake_api, study, "org", "az", rows[0].npm_name, force=True)
    assert n == 1
    assert manifest.read(study.manifest_path)[0].state == "pending"


def test_retry_one_targets_a_specific_date(fake_api, study):
    rows = [
        row(git_url="https://github.com/a/a", snapshot_date="2024-01-01", state="failed", error="e"),
        row(git_url="https://github.com/a/a", snapshot_date="2024-04-01", state="failed", error="e"),
    ]
    manifest.write_all(study.manifest_path, rows)
    n = pipeline.retry_one(fake_api, study, "org", "az", rows[0].npm_name, snapshot_date="2024-01-01")
    assert n == 1
    out = {r.snapshot_date: r.state for r in manifest.read(study.manifest_path)}
    assert out["2024-01-01"] == "pending"
    assert out["2024-04-01"] == "failed"


# ---- poll ---------------------------------------------------------------------


def test_poll_happy_terminal_persists_two_blobs_and_marks_done(fake_api, study):
    aid = fake_api.start_analysis("org", "proj1", "az", "main")
    manifest.write_all(study.manifest_path, [row(project_id="proj1", analysis_id=aid, state="pending")])
    pipeline.poll(fake_api, study, "org")
    r = manifest.read(study.manifest_path)[0]
    assert r.state == "done"
    assert r.server_status == "completed"
    out_dir = study.raw_dir / "proj1" / aid
    assert (out_dir / "js-sbom.json").exists()
    assert (out_dir / "vuln-finder.json").exists()
    assert not (out_dir / "license-finder.json").exists()


def test_poll_sad_terminal_records_failure_reason(fake_api, study):
    aid = fake_api.start_analysis("org", "proj1", "az", "main")
    fake_api.set_status(aid, "failure", failure_reason="CommitUnresolvable: commit x in y: z")
    manifest.write_all(study.manifest_path, [row(project_id="proj1", analysis_id=aid, state="pending")])
    pipeline.poll(fake_api, study, "org")
    r = manifest.read(study.manifest_path)[0]
    assert r.state == "failed"
    assert r.error == "CommitUnresolvable: commit x in y: z"


def test_poll_analysis_missing_from_list_is_failed(fake_api, study):
    manifest.write_all(study.manifest_path, [row(project_id="proj1", analysis_id="ghost", state="pending")])
    pipeline.poll(fake_api, study, "org")
    r = manifest.read(study.manifest_path)[0]
    assert r.state == "failed"
    assert "not found" in r.error


def test_poll_ceiling_fails_a_stuck_updating_db_row(fake_api, study):
    aid = fake_api.start_analysis("org", "proj1", "az", "main")
    fake_api.set_status(aid, "updating_db")
    manifest.write_all(study.manifest_path, [row(project_id="proj1", analysis_id=aid, state="pending")])
    pipeline.poll(fake_api, study, "org", give_up_hours=0)
    r = manifest.read(study.manifest_path)[0]
    assert r.state == "failed"
    assert "client ceiling" in r.error
    assert "updating_db" in r.error


def test_poll_noop_when_nothing_pending(fake_api, study):
    manifest.write_all(study.manifest_path, [row(state="done")])
    pipeline.poll(fake_api, study, "org")  # must not raise
