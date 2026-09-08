from __future__ import annotations

import json

import pandas as pd
import pytest

from js_vuln_study import numbers
from js_vuln_study.config import Study

from conftest import row, write_manifest, write_tables


def _study(tmp_path, name="s") -> Study:
    d = tmp_path / name
    d.mkdir()
    (d / "study.toml").write_text(f'[study]\nname = "{name}"\n', encoding="utf-8")
    return Study.load(d)


def _vuln_row(pid, npm, snap, vid, dep, **over):
    rec = {
        "analysis_id": f"{pid}-{snap}", "project_id": pid, "npm_name": npm, "snapshot_date": snap,
        "vulnerability_id": vid, "affected_dependency": dep, "affected_version": "1.0.0",
        "severity_class": "HIGH", "epss_score": 0.1, "epss_percentile": 0.5,
        "conflict_flag": "MATCH_CORRECT", "winning_source": "NVD",
        "direct_dependency": True, "published_date": "2023-01-01T00:00:00Z",
        "modified_date": None, "withdrawn_date": None,
    }
    rec.update(over)
    return rec


def _analysis_row(pid, npm, snap, **over):
    rec = {
        "analysis_id": f"{pid}-{snap}", "project_id": pid, "npm_name": npm, "tier": "t", "rank": 0,
        "git_url": f"https://github.com/{npm}", "snapshot_date": snap, "commit_hash": "a" * 40,
        "committed_at": "2024-01-01T00:00:00Z" if snap == "HEAD" else None,
        "total_dependencies": 5, "package_manager": "NPM", "total_vulnerabilities": 1,
        "run_id": "r1",
    }
    rec.update(over)
    return rec


@pytest.fixture
def populated_study(tmp_path) -> Study:
    s = _study(tmp_path)
    grid = ["2024-01-01", "2024-02-01"]
    write_manifest(s.manifest_path, [
        row(npm_name="p/one", git_url="https://github.com/p/one", snapshot_date="HEAD", state="done"),
        row(npm_name="p/one", git_url="https://github.com/p/one", snapshot_date="2024-01-01", state="done"),
        row(npm_name="p/one", git_url="https://github.com/p/one", snapshot_date="2024-02-01", state="done"),
        row(npm_name="p/two", git_url="https://github.com/p/two", snapshot_date="HEAD", state="done"),
        row(npm_name="p/two", git_url="https://github.com/p/two", snapshot_date="2024-01-01", state="failed", error="boom"),
    ])
    write_tables(
        s.tables_dir,
        analyses_rows=[
            _analysis_row("p1", "p/one", "HEAD"), _analysis_row("p1", "p/one", "2024-01-01"),
            _analysis_row("p1", "p/one", "2024-02-01"), _analysis_row("p2", "p/two", "HEAD"),
        ],
        vulns_rows=[
            _vuln_row("p1", "p/one", "HEAD", "CVE-1", "lodash"),
            _vuln_row("p1", "p/one", "2024-01-01", "CVE-1", "lodash"),
            _vuln_row("p2", "p/two", "HEAD", "CVE-2", "tar", severity_class="CRITICAL"),
        ],
        run_meta={"run_id": "r1", "knowledge": {"knowledge_sources": {"nvd": "2026-08-01"}, "epss_rows": 10},
                  "analyzer_steps": [], "api_version": "1.0"},
    )
    return s


def test_coverage_grid_length_is_derived_not_hardcoded(populated_study):
    out = numbers.build_numbers(populated_study)
    assert out["coverage"]["grid_len"] == 2
    # only p/one completed both dated snapshots
    assert out["coverage"]["balanced_panel"] == 1
    assert out["coverage"]["skip_markers"] == 0
    assert out["coverage"]["failures"]["total"] == 1


def test_build_numbers_produces_documented_top_level_keys(populated_study):
    out = numbers.build_numbers(populated_study)
    for key in ("run_meta", "coverage", "headline", "sweep", "epss", "match_flags",
                "winning_source_head", "disclosure_coverage_hist", "survival_residence",
                "survival_disclosed", "rqc", "rqd", "trajectory_balanced", "trajectory_balanced_meta"):
        assert key in out, key
    assert out["headline"]["n_projects"] == 2  # HEAD slice: p/one and p/two


def test_build_numbers_writes_results_numbers_json(populated_study):
    numbers.build_numbers(populated_study)
    dest = populated_study.tables_dir / "results_numbers.json"
    assert dest.exists()
    assert json.loads(dest.read_text())["coverage"]["grid_len"] == 2


def test_build_numbers_optional_keys_absent_without_remediation_or_triangulation(populated_study):
    out = numbers.build_numbers(populated_study)
    assert "survival_day_resolution" not in out
    assert "triangulation" not in out
    assert "cohort" not in out


def test_survival_day_resolution_present_when_events_exist(populated_study):
    write_tables(
        populated_study.tables_dir,
        analyses_rows=json.loads(pd.read_parquet(populated_study.tables_dir / "analyses.parquet").to_json(orient="records")),
        vulns_rows=json.loads(pd.read_parquet(populated_study.tables_dir / "vulns.parquet").to_json(orient="records")),
        run_meta=json.loads((populated_study.tables_dir / "run_meta.json").read_text()),
        events_rows=[
            {"npm_name": "p/one", "project_id": "p1", "affected_dependency": "lodash",
             "affected_version": "1.0.0", "last_seen": "2024-01-01", "next_snapshot": "2024-02-01",
             "lockfile": "yarn.lock", "fix_commit_sha": "f" * 40, "fixed_at": "2024-01-10T00:00:00Z",
             "fix_kind": "upgraded", "fix_to_version": "1.0.1", "method": "linear_scan", "status": "found"},
        ],
    )
    out = numbers.build_numbers(populated_study)
    assert "survival_day_resolution" in out
    assert out["survival_day_resolution"]["events"] == 1


def test_compare_cohorts_knowledge_stamp_mismatch_is_flagged(tmp_path, caplog):
    base = _study(tmp_path, "base")
    cohort = _study(tmp_path, "cohort")
    for s, stamp in ((base, "2026-01-01"), (cohort, "2026-06-01")):
        write_tables(
            s.tables_dir,
            analyses_rows=[_analysis_row("p1", "x/y", "HEAD")],
            vulns_rows=[_vuln_row("p1", "x/y", "HEAD", "CVE-1", "lodash")],
            run_meta={"knowledge": {"knowledge_sources": {"nvd": stamp}, "epss_rows": 1}},
        )
    with caplog.at_level("WARNING"):
        result = numbers.compare_cohorts(base, cohort)
    assert result["meta"]["knowledge_stamps_match"] is False
    assert any("knowledge drift" in r.message for r in caplog.records)


def test_compare_cohorts_matching_stamps_no_warning(tmp_path, caplog):
    base = _study(tmp_path, "base")
    cohort = _study(tmp_path, "cohort")
    for s in (base, cohort):
        write_tables(
            s.tables_dir,
            analyses_rows=[_analysis_row("p1", "x/y", "HEAD")],
            vulns_rows=[_vuln_row("p1", "x/y", "HEAD", "CVE-1", "lodash")],
            run_meta={"knowledge": {"knowledge_sources": {"nvd": "2026-01-01"}, "epss_rows": 1}},
        )
    with caplog.at_level("WARNING"):
        result = numbers.compare_cohorts(base, cohort)
    assert result["meta"]["knowledge_stamps_match"] is True
    assert not any("knowledge drift" in r.message for r in caplog.records)
