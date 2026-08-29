"""Tests for scripts/passbolt_compare.py — synthetic two-cohort fixtures
through `compute()`: KM medians, recency split, small-stratum skipping, and
the knowledge-stamp mismatch warning."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from passbolt_compare import compute  # noqa: E402


def _mk_cohort(tmp_path: Path, name: str, knowledge: dict) -> Path:
    """Cohort dir: one project, snapshots 2024-01/04/07, 12 disclosed vulns
    present at the first two snapshots and gone at the third — 12 event=1
    intervals of 182 days. Publication dates: 6 pre-2024, 6 on the 2024-01-01
    cutoff."""
    d = tmp_path / name
    tables = d / "tables"
    tables.mkdir(parents=True)
    analyses = pd.DataFrame([
        {"project_id": "p1", "npm_name": f"{name}/repo", "git_url": f"https://github.com/{name}/repo",
         "analysis_id": f"a-{s}", "snapshot_date": s, "commit_hash": f"sha-{s}",
         "committed_at": f"{s}T00:00:00Z"}
        for s in ("2024-01-01", "2024-04-01", "2024-07-01")
    ])
    vulns = pd.DataFrame([
        {"project_id": "p1", "npm_name": f"{name}/repo", "snapshot_date": s,
         "analysis_id": f"a-{s}", "vulnerability_id": f"CVE-{i}",
         "affected_dependency": f"dep{i}", "affected_version": "1.0.0",
         "severity_class": "HIGH",
         "published_date": "2023-06-01T00:00:00Z" if i < 6 else "2024-01-01T00:00:00Z"}
        for i in range(12) for s in ("2024-01-01", "2024-04-01")
    ])
    analyses.to_parquet(tables / "analyses.parquet", index=False)
    vulns.to_parquet(tables / "vulns.parquet", index=False)
    (tables / "run_meta.json").write_text(json.dumps({"knowledge": knowledge}))
    return d


def test_compute_pooled_and_recency(tmp_path):
    k = {"knowledge_sources": {"nvd": "2026-08-03", "osv": None}, "epss_rows": 5}
    base = _mk_cohort(tmp_path, "base", k)
    cohort = _mk_cohort(tmp_path, "passbolt", k)
    got = compute(base, cohort, recency_cutoff="2024-01-01")

    assert got["meta"]["knowledge_stamps"]["match"] is True
    for side in ("baseline", "cohort"):
        block = got[side]
        assert block["intervals"] == 12
        assert block["pooled"]["n"] == 12
        assert block["pooled"]["n_fixed"] == 12
        assert block["pooled"]["km_median_days"] == 182.0
        # 6 + 6 recency split: both below MIN_STRATUM -> n reported, no fit
        rec = block["recency"]
        assert rec["disclosed_on_or_after"]["n"] == 6
        assert rec["disclosed_on_or_after"]["km_median_days"] is None
        assert rec["disclosed_before"]["n"] == 6
        # single severity class: HIGH fits, others are empty
        assert block["by_severity"]["HIGH"]["km_median_days"] == 182.0
        assert block["by_severity"]["CRITICAL"]["n"] == 0
        assert block["by_severity"]["CRITICAL"]["km_median_days"] is None
        # no remediation parquet: nothing day-resolved, upgrade_only == pooled
        assert block["pooled"]["n_day_resolution"] == 0
        assert block["upgrade_only"]["n_removed_dropped"] == 0
        assert block["upgrade_only"]["pooled"]["km_median_days"] == 182.0
        assert list(block["by_repo"]) == [f"{block['data_dir']}/repo"]


def test_compute_upgrade_only_drops_every_removal_flavor(tmp_path):
    k = {"knowledge_sources": {"nvd": "2026-08-03", "osv": None}, "epss_rows": 5}
    base = _mk_cohort(tmp_path, "base", k)
    cohort = _mk_cohort(tmp_path, "passbolt", k)
    # Mine day-resolution fixes for dep0 (removed_direct), dep1
    # (removed_transitive), dep2 (legacy unsplit removed) — all should drop
    # from upgrade_only in both cohorts, and all three should show up
    # distinctly in fix_kind_split.
    events = pd.DataFrame([
        {"npm_name": f"{name}/repo", "project_id": "p1", "affected_dependency": dep,
         "affected_version": "1.0.0", "workspace_scope": "root",
         "last_seen": "2024-04-01", "next_snapshot": "2024-07-01",
         "lockfile": "yarn.lock", "fix_commit_sha": f"fix-{dep}",
         "fixed_at": "2024-04-20T00:00:00Z", "method": "linear_scan",
         "status": "found", "fix_kind": kind, "fix_to_version": None}
        for name in ("base", "passbolt")
        for dep, kind in [("dep0", "removed_direct"), ("dep1", "removed_transitive"),
                          ("dep2", "removed")]
    ])
    (base / "tables" / "remediation_events.parquet").parent.mkdir(exist_ok=True)
    events[events.npm_name == "base/repo"].to_parquet(
        base / "tables" / "remediation_events.parquet", index=False)
    events[events.npm_name == "passbolt/repo"].to_parquet(
        cohort / "tables" / "remediation_events.parquet", index=False)

    got = compute(base, cohort, recency_cutoff="2024-01-01")
    for side in ("baseline", "cohort"):
        block = got[side]
        assert block["fix_kind_split"] == {
            "removed_direct": 1, "removed_transitive": 1, "removed": 1,
        }
        assert block["upgrade_only"]["n_removed_dropped"] == 3
        # the 3 removed intervals are gone from upgrade_only's pooled n but
        # the other 9 (unaffected deps) stay
        assert block["upgrade_only"]["pooled"]["n"] == 9
        assert block["pooled"]["n"] == 12


def test_compute_flags_stamp_mismatch(tmp_path, caplog):
    base = _mk_cohort(tmp_path, "base", {"knowledge_sources": {"nvd": "2026-08-03"}, "epss_rows": 5})
    cohort = _mk_cohort(tmp_path, "passbolt", {"knowledge_sources": {"nvd": "2026-09-01"}, "epss_rows": 5})
    with caplog.at_level(logging.WARNING):
        got = compute(base, cohort)
    assert got["meta"]["knowledge_stamps"]["match"] is False
    assert any("knowledge stamps differ" in r.message for r in caplog.records)


def test_compute_missing_run_meta_is_mismatch(tmp_path):
    base = _mk_cohort(tmp_path, "base", {"knowledge_sources": {"nvd": "2026-08-03"}, "epss_rows": 5})
    cohort = _mk_cohort(tmp_path, "passbolt", {"knowledge_sources": {"nvd": "2026-08-03"}, "epss_rows": 5})
    (cohort / "tables" / "run_meta.json").unlink()
    got = compute(base, cohort)
    assert got["meta"]["knowledge_stamps"]["match"] is False
