"""Unit tests for the June->August drift decomposition.

Everything here is filesystem-only (tiny hand-built parquet runs in tmp_path)
— no API, no network. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import drift_decomposition as dd  # noqa: E402

LIVE_KNOWLEDGE = "2026-08-03T00:00:00Z"


def _arow(npm: str, snap: str, commit: str) -> dict:
    return {"npm_name": npm, "snapshot_date": snap, "commit_hash": commit}


def _vrow(npm: str, snap: str, vid: str, dep: str, src: str = "OSV",
          published: str | None = "2026-01-01T00:00:00Z", version: str = "1.0.0") -> dict:
    return {
        "npm_name": npm,
        "snapshot_date": snap,
        "workspace": ".",
        "vulnerability_id": vid,
        "affected_dependency": dep,
        "affected_version": version,
        "winning_source": src,
        "published_date": published,
    }


def _write_run(run_dir: Path, analyses: list[dict], vulns: list[dict],
               knowledge_ts: str | None = None, epss_rows: int | None = None) -> Path:
    tables = run_dir / "tables"
    tables.mkdir(parents=True)
    pd.DataFrame(analyses, columns=["npm_name", "snapshot_date", "commit_hash"]).to_parquet(
        tables / "analyses.parquet")
    pd.DataFrame(vulns, columns=list(_vrow("x", "HEAD", "CVE-0", "d"))).to_parquet(
        tables / "vulns.parquet")
    if knowledge_ts is not None:
        json.dump(
            {"knowledge": {"knowledge_sources": {"nvd": knowledge_ts, "npm": "0"}, "epss_rows": epss_rows}},
            open(tables / "run_meta.json", "w"),
        )
    return run_dir


@pytest.fixture
def runs(tmp_path) -> dict:
    """Two-run universe exercising every decomposition path.

    p1: dated pair, same commit — CVE-1 in both, CVE-2 new in live (30d-old
        advisory), CVE-3 (GCVE) vanished from live.
    p2: HEAD pair, DIFFERENT commit — 1 archive row vs 3 live rows, so the
        raw HEAD delta moves while the same-commit HEAD delta cannot.
    p3: HEAD pair, same commit — CVE-6 in both, CVE-7 new in live with an
        unknown published_date.
    p4/p5: one-sided (archive-only / live-only) — excluded from every delta.
    """
    archive = _write_run(
        tmp_path / "archive",
        [_arow("p1", "2024-01-01", "c1"), _arow("p2", "HEAD", "old"),
         _arow("p3", "HEAD", "c3"), _arow("p4", "2024-01-01", "c4")],
        [_vrow("p1", "2024-01-01", "CVE-1", "lodash"),
         _vrow("p1", "2024-01-01", "CVE-3", "tar", src="GCVE"),
         _vrow("p2", "HEAD", "CVE-4", "glob"),
         _vrow("p3", "HEAD", "CVE-6", "semver"),
         _vrow("p4", "2024-01-01", "CVE-8", "chalk")],
        knowledge_ts="2026-06-29T00:00:00Z", epss_rows=100,
    )
    live = _write_run(
        tmp_path / "live",
        [_arow("p1", "2024-01-01", "c1"), _arow("p2", "HEAD", "new"),
         _arow("p3", "HEAD", "c3"), _arow("p5", "HEAD", "c5")],
        [_vrow("p1", "2024-01-01", "CVE-1", "lodash"),
         _vrow("p1", "2024-01-01", "CVE-2", "minimist", published="2026-07-04T00:00:00Z"),
         _vrow("p2", "HEAD", "CVE-4", "glob"),
         _vrow("p2", "HEAD", "CVE-5", "ms"),
         _vrow("p2", "HEAD", "CVE-5b", "ms"),
         _vrow("p3", "HEAD", "CVE-6", "semver"),
         _vrow("p3", "HEAD", "CVE-7", "yargs", published=None),
         _vrow("p5", "HEAD", "CVE-9", "debug")],
        knowledge_ts=LIVE_KNOWLEDGE, epss_rows=110,
    )
    return {"archive": archive, "live": live, "out": dd.decompose(archive, live)}


# ---- pairing / same-commit logic ---------------------------------------------


def test_pairing_counts_and_one_sided_keys(runs):
    p = runs["out"]["pairing"]
    assert p["n_pairs"] == 3
    assert p["archive_only"] == 1  # p4
    assert p["live_only"] == 1     # p5
    assert p["same_commit"]["overall"] == {"same_commit": 2, "different_commit": 1, "n_pairs": 3}
    assert p["same_commit"]["head"] == {"same_commit": 1, "different_commit": 1, "n_pairs": 2}
    assert p["same_commit"]["dated"] == {"same_commit": 1, "different_commit": 0, "n_pairs": 1}


def test_totals_are_all_rows_including_one_sided(runs):
    t = runs["out"]["totals"]
    assert t["instances"] == {"archive": 5, "live": 8, "raw_delta_pct": pytest.approx(60.0)}
    assert t["instances_head"]["archive"] == 2 and t["instances_head"]["live"] == 6
    assert t["instances_head"]["raw_delta_pct"] == pytest.approx(200.0)


# ---- raw vs same-commit delta separation --------------------------------------


def test_raw_delta_includes_code_movement_same_commit_excludes_it(runs):
    d = runs["out"]["deltas"]
    # paired keys only: archive 4 rows (p4 dropped), live 7 rows (p5 dropped)
    assert d["paired_all"]["overall"] == {
        "n_pairs": 3, "archive_instances": 4, "live_instances": 7, "delta_pct": pytest.approx(75.0)}
    # p2's commit changed: its 1 -> 3 jump is visible raw...
    assert d["paired_all"]["head"] == {
        "n_pairs": 2, "archive_instances": 2, "live_instances": 5, "delta_pct": pytest.approx(150.0)}
    # ...but excluded from the same-commit (pure knowledge drift) view.
    assert d["same_commit"]["overall"] == {
        "n_pairs": 2, "archive_instances": 3, "live_instances": 4, "delta_pct": pytest.approx(100 / 3)}
    assert d["same_commit"]["head"] == {
        "n_pairs": 1, "archive_instances": 1, "live_instances": 2, "delta_pct": pytest.approx(100.0)}


def test_delta_pct_none_when_archive_side_empty(tmp_path):
    archive = _write_run(tmp_path / "archive", [_arow("p1", "HEAD", "c1")], [])
    live = _write_run(tmp_path / "live", [_arow("p1", "HEAD", "c1")],
                      [_vrow("p1", "HEAD", "CVE-1", "lodash")])
    out = dd.decompose(archive, live)
    assert out["deltas"]["same_commit"]["head"]["delta_pct"] is None
    assert out["totals"]["instances"]["raw_delta_pct"] is None


# ---- winning_source decomposition ---------------------------------------------


def test_winning_source_deltas_absolute_and_relative(runs):
    src = runs["out"]["by_winning_source"]
    # paired keys: OSV 3->7, GCVE 1->0 (vanished CVE-3)
    assert src["paired_all_overall"]["OSV"] == {
        "archive": 3, "live": 7, "abs_delta": 4, "rel_delta_pct": pytest.approx(400 / 3)}
    assert src["paired_all_overall"]["GCVE"] == {
        "archive": 1, "live": 0, "abs_delta": -1, "rel_delta_pct": pytest.approx(-100.0)}
    # same-commit keys drop p2 entirely: OSV 2->4
    assert src["same_commit_overall"]["OSV"]["archive"] == 2
    assert src["same_commit_overall"]["OSV"]["live"] == 4
    # a source with no archive rows would have rel None
    assert src["paired_all_overall"].get("NVD") is None


# ---- advisory-age binning -----------------------------------------------------


def test_age_bins_boundaries_and_unknown():
    ref = pd.Timestamp(LIVE_KNOWLEDGE)
    pub = pd.Series([
        "2026-08-01T00:00:00Z",  # 2d   -> <30d
        "2026-07-04T00:00:00Z",  # 30d  -> 30-90d (left-closed boundary)
        "2026-01-01T00:00:00Z",  # 214d -> 90-365d
        "2024-08-03T00:00:00Z",  # 730d -> 1-3y
        "2019-01-01T00:00:00Z",  #      -> >3y
        None,                    #      -> unknown
        "not-a-date",            #      -> unknown
    ])
    assert dd._age_bins(pub, ref) == {
        "<30d": 1, "30-90d": 1, "90-365d": 1, "1-3y": 1, ">3y": 1, "unknown": 2, "n": 7}


def test_age_bins_without_reference_date_all_unknown():
    assert dd._age_bins(pd.Series(["2026-01-01T00:00:00Z"]), None) == {
        "<30d": 0, "30-90d": 0, "90-365d": 0, "1-3y": 0, ">3y": 0, "unknown": 1, "n": 1}


def test_new_instance_age_bins_on_same_commit_subset(runs):
    age = runs["out"]["advisory_age_new_instances"]
    assert age["reference_date"] == str(pd.Timestamp(LIVE_KNOWLEDGE))
    # new on same-commit pairs: CVE-2 (published 30d before ref) + CVE-7 (no date);
    # p2's new rows are code movement, not knowledge churn, and must NOT appear.
    assert age["new_same_commit"] == {
        "<30d": 0, "30-90d": 1, "90-365d": 0, "1-3y": 0, ">3y": 0, "unknown": 1, "n": 2}
    assert age["baseline_all_live_same_commit"]["n"] == 4


# ---- churn --------------------------------------------------------------------


def test_churn_directions_and_pair_counts_on_same_commit_subset(runs):
    ch = runs["out"]["churn_same_commit"]
    assert ch["n_pairs"] == 2
    assert ch["new_instances"] == 2       # CVE-2/minimist, CVE-7/yargs
    assert ch["vanished_instances"] == 1  # CVE-3/tar
    assert ch["new_vuln_package_pairs"] == 2
    assert ch["vanished_vuln_package_pairs"] == 1


# ---- run_meta plumbing --------------------------------------------------------


def test_meta_carries_knowledge_dates_and_epss_rows(runs):
    meta = runs["out"]["meta"]
    assert meta["epss_rows"] == {"archive": 100, "live": 110}
    # max parseable source stamp; the "0" npm placeholder must not win
    assert meta["knowledge_date"]["archive"] == str(pd.Timestamp("2026-06-29T00:00:00Z"))
    assert meta["knowledge_date"]["live"] == str(pd.Timestamp(LIVE_KNOWLEDGE))
    assert len(meta["caveats"]) == 3


def test_missing_run_meta_degrades_to_none(tmp_path):
    archive = _write_run(tmp_path / "archive", [_arow("p1", "HEAD", "c1")],
                         [_vrow("p1", "HEAD", "CVE-1", "lodash")])
    live = _write_run(tmp_path / "live", [_arow("p1", "HEAD", "c1")],
                      [_vrow("p1", "HEAD", "CVE-1", "lodash"),
                       _vrow("p1", "HEAD", "CVE-2", "tar")])
    out = dd.decompose(archive, live)
    assert out["meta"]["knowledge_date"] == {"archive": None, "live": None}
    assert out["meta"]["epss_rows"] == {"archive": None, "live": None}
    # no reference date -> every new instance is age-unknown
    assert out["advisory_age_new_instances"]["new_same_commit"] == {
        "<30d": 0, "30-90d": 0, "90-365d": 0, "1-3y": 0, ">3y": 0, "unknown": 1, "n": 1}


def test_output_is_json_serialisable(runs):
    json.dumps(runs["out"])
