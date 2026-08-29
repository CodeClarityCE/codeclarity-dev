from __future__ import annotations

import json

from js_vuln_study import manifest as m

from conftest import row


def test_round_trip_preserves_every_field(tmp_path):
    path = tmp_path / "manifest.jsonl"
    r = row(state="failed", error="boom", attempts=1, knowledge_asof="2026-08-03", run_id="abc123")
    m.write_all(path, [r])
    back = m.read(path)
    assert back == [r]


def test_atomic_rewrite_leaves_no_tmp_file(tmp_path):
    path = tmp_path / "manifest.jsonl"
    m.write_all(path, [row()])
    assert path.exists()
    assert not path.with_suffix(".jsonl.tmp").exists()


def test_star_sentinel_is_a_legal_snapshot_date(tmp_path):
    path = tmp_path / "manifest.jsonl"
    r = row(snapshot_date="*", state="skipped", project_id=None, analysis_id=None, error="import failed")
    m.write_all(path, [r])
    back = m.read(path)
    assert back[0].snapshot_date == "*"
    assert back[0].key() == (r.git_url, "*")


def test_normalize_status_maps_every_legacy_word():
    assert m.normalize_status("submitted") == "pending"
    assert m.normalize_status("completed") == "done"
    assert m.normalize_status("success") == "done"
    assert m.normalize_status("failure") == "failed"
    assert m.normalize_status("failed") == "failed"
    assert m.normalize_status("cancelled") == "failed"
    assert m.normalize_status("failed-submit") == "failed"
    assert m.normalize_status("skipped") == "skipped"
    assert m.normalize_status("pending") == "pending"  # already a new-vocabulary word


def test_read_normalizes_a_legacy_manifest_line(tmp_path):
    path = tmp_path / "manifest.jsonl"
    legacy = {
        "npm_name": "vuejs/core", "tier": "top-100", "rank": 0,
        "git_url": "https://github.com/vuejs/core", "branch": "main",
        "snapshot_date": "HEAD", "commit_hash": "a" * 40, "committed_at": "2026-01-01T00:00:00Z",
        "project_id": "p1", "analysis_id": "a1", "status": "completed", "error": None,
    }
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    rows = m.read(path)
    assert len(rows) == 1
    assert rows[0].state == "done"
    assert rows[0].server_status == "completed"
    assert rows[0].attempts == 0
    assert rows[0].run_id is None


def test_read_missing_file_returns_empty_list(tmp_path):
    assert m.read(tmp_path / "nope.jsonl") == []


def test_append_adds_a_line_without_touching_existing_rows(tmp_path):
    path = tmp_path / "manifest.jsonl"
    m.write_all(path, [row(git_url="https://github.com/a/a", snapshot_date="HEAD")])
    m.append(path, row(git_url="https://github.com/b/b", snapshot_date="HEAD"))
    rows = m.read(path)
    assert len(rows) == 2
    assert {r.git_url for r in rows} == {"https://github.com/a/a", "https://github.com/b/b"}
