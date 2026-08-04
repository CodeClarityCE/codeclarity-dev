"""Unit tests for the ladder dose-response aggregation.

Everything here is filesystem-only (tiny hand-built parquet rungs in tmp_path)
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

import ladder_dose_response as ld  # noqa: E402

URL1, URL2 = "https://github.com/o/r1", "https://github.com/o/r2"
C1, C2 = "1" * 40, "2" * 40


def _arow(url: str, commit: str) -> dict:
    return {"git_url": url, "commit_hash": commit}


def _vrow(url: str, commit: str, vid: str, dep: str, sev: str = "HIGH",
          src: str = "OSV", version: str = "1.0.0") -> dict:
    return {
        "git_url": url,
        "commit_hash": commit,
        "workspace": ".",
        "vulnerability_id": vid,
        "affected_dependency": dep,
        "affected_version": version,
        "severity_class": sev,
        "winning_source": src,
    }


def _write_rung(run_dir: Path, analyses: list[dict], vulns: list[dict],
                sources: dict | None = None, api_sha: str = "api-A",
                backend_sha: str = "backend-B", epss_rows: int | None = 10) -> Path:
    tables = run_dir / "tables"
    tables.mkdir(parents=True)
    pd.DataFrame(analyses, columns=["git_url", "commit_hash"]).to_parquet(
        tables / "analyses.parquet")
    pd.DataFrame(vulns, columns=list(_vrow("x", "c", "CVE-0", "d"))).to_parquet(
        tables / "vulns.parquet")
    if sources is not None:
        json.dump(
            {"api_sha": api_sha, "backend_sha": backend_sha,
             "knowledge": {"knowledge_sources": sources, "epss_rows": epss_rows}},
            open(tables / "run_meta.json", "w"),
        )
    return run_dir


# The frozen nvd/gcve stamps stay at the natural dump in every rung — the OSV
# stamp alone carries the rung's dated state.
FROZEN = {"nvd": "2026-08-03T00:00:00Z", "npm": "0", "gcve": "2026-08-03T00:00:00Z"}


def _osv(ts: str) -> dict:
    return {**FROZEN, "osv": ts}


@pytest.fixture
def rungs(tmp_path) -> dict:
    """Three-rung ladder exercising the common-subset and delta paths.

    stale (osv 2023): completed C1 only — C2 missing, so common = {C1}.
    mid   (osv 2025): C1 + C2; C1 carries CVE-1, C2 carries CVE-9 (excluded
          from common counts).
    fresh (osv 2026-06-29): C1 + C2; C1 carries CVE-1 + CVE-3, C2 CVE-9.
    """
    stale = _write_rung(
        tmp_path / "rung-2023",
        [_arow(URL1, C1)],
        [_vrow(URL1, C1, "CVE-1", "lodash")],
        sources=_osv("2023-01-01T00:00:00Z"), epss_rows=1,
    )
    mid = _write_rung(
        tmp_path / "rung-2025",
        [_arow(URL1, C1), _arow(URL2, C2)],
        [_vrow(URL1, C1, "CVE-1", "lodash"),
         _vrow(URL2, C2, "CVE-9", "debug")],
        sources=_osv("2025-01-01T00:00:00Z"), epss_rows=5,
    )
    fresh = _write_rung(
        tmp_path / "rung-fresh",
        [_arow(URL1, C1), _arow(URL2, C2)],
        [_vrow(URL1, C1, "CVE-1", "lodash"),
         _vrow(URL1, C1, "CVE-3", "tar", sev="CRITICAL", src="NVD"),
         _vrow(URL2, C2, "CVE-9", "debug")],
        sources=_osv("2026-06-29T00:00:00Z"),
    )
    # Deliberately shuffled input order — compute() must sort by knowledge date.
    return {"dirs": [mid, fresh, stale], "out": ld.compute([mid, fresh, stale])}


# ---- ordering ----------------------------------------------------------------


def test_rungs_sorted_stalest_to_freshest_by_osv_date(rungs):
    assert [Path(r["dir"]).name for r in rungs["out"]["rungs"]] == [
        "rung-2023", "rung-2025", "rung-fresh",
    ]
    assert rungs["out"]["meta"]["freshest"].endswith("rung-fresh")
    # The frozen nvd/gcve stamps (2026-08) must NOT outrank the dated OSV stamp.
    assert rungs["out"]["rungs"][0]["knowledge_date"] == str(pd.Timestamp("2023-01-01T00:00:00Z"))


def test_dateless_rung_sorts_first_with_warning(tmp_path, caplog):
    a = _write_rung(tmp_path / "a", [_arow(URL1, C1)], [], sources=_osv("2024-01-01T00:00:00Z"))
    b = _write_rung(tmp_path / "b", [_arow(URL1, C1)], [])  # no run_meta at all
    with caplog.at_level("WARNING"):
        out = ld.compute([a, b])
    assert [Path(r["dir"]).name for r in out["rungs"]] == ["b", "a"]
    assert out["rungs"][0]["knowledge_date"] is None
    assert any("no parseable knowledge date" in r.message for r in caplog.records)


# ---- common-subset restriction ----------------------------------------------


def test_common_subset_is_key_intersection(rungs):
    assert rungs["out"]["meta"]["common_analyses"] == 1  # C1 only
    by_name = {Path(r["dir"]).name: r for r in rungs["out"]["rungs"]}
    # mid: 2 instances total, but only C1's CVE-1 is on the common subset
    assert by_name["rung-2025"]["instances_total"] == 2
    assert by_name["rung-2025"]["instances_common"] == 1
    assert by_name["rung-fresh"]["instances_total"] == 3
    assert by_name["rung-fresh"]["instances_common"] == 2
    # per-rung completed-analysis counts are unrestricted
    assert by_name["rung-2023"]["n_analyses"] == 1
    assert by_name["rung-fresh"]["n_analyses"] == 2


def test_mixes_are_computed_on_common_subset(rungs):
    by_name = {Path(r["dir"]).name: r for r in rungs["out"]["rungs"]}
    # C2's CVE-9 (HIGH/OSV) must not leak into the common-subset mixes.
    assert by_name["rung-2025"]["severity_mix_common"] == {"HIGH": 1}
    assert by_name["rung-fresh"]["severity_mix_common"] == {"HIGH": 1, "CRITICAL": 1}
    assert by_name["rung-fresh"]["winning_source_mix_common"] == {"OSV": 1, "NVD": 1}


# ---- deltas / jaccard vs freshest --------------------------------------------


def test_delta_and_jaccard_vs_freshest(rungs):
    by_name = {Path(r["dir"]).name: r for r in rungs["out"]["rungs"]}
    stale = by_name["rung-2023"]["vs_freshest"]
    assert stale["instance_delta_common"] == -1  # 1 vs fresh's 2
    assert stale["instance_delta_pct"] == pytest.approx(-50.0)
    # pairs: {(lodash, CVE-1)} vs {(lodash, CVE-1), (tar, CVE-3)} -> 1/2
    assert stale["jaccard_pairs"] == pytest.approx(0.5)
    fresh = by_name["rung-fresh"]["vs_freshest"]
    assert fresh["instance_delta_common"] == 0
    assert fresh["instance_delta_pct"] == pytest.approx(0.0)
    assert fresh["jaccard_pairs"] == pytest.approx(1.0)


def test_delta_pct_none_when_freshest_common_is_empty(tmp_path):
    a = _write_rung(tmp_path / "a", [_arow(URL1, C1)],
                    [_vrow(URL1, C1, "CVE-1", "lodash")],
                    sources=_osv("2024-01-01T00:00:00Z"))
    b = _write_rung(tmp_path / "b", [_arow(URL2, C2)], [],
                    sources=_osv("2025-01-01T00:00:00Z"))
    out = ld.compute([a, b])
    assert out["meta"]["common_analyses"] == 0
    stale = out["rungs"][0]["vs_freshest"]
    assert stale["instance_delta_pct"] is None
    assert stale["jaccard_pairs"] is None  # both pair sets empty


# ---- SHA-mismatch warning path -----------------------------------------------


def test_identical_shas_do_not_warn(rungs, caplog):
    assert rungs["out"]["meta"]["sha_mismatch"] is False


def test_sha_mismatch_warns_but_does_not_crash(tmp_path, caplog):
    a = _write_rung(tmp_path / "a", [_arow(URL1, C1)], [],
                    sources=_osv("2024-01-01T00:00:00Z"), backend_sha="backend-B")
    b = _write_rung(tmp_path / "b", [_arow(URL1, C1)], [],
                    sources=_osv("2025-01-01T00:00:00Z"), backend_sha="backend-OTHER")
    with caplog.at_level("WARNING"):
        out = ld.compute([a, b])
    assert out["meta"]["sha_mismatch"] is True
    assert any("api_sha/backend_sha differ" in r.message for r in caplog.records)
    shas = out["meta"]["shas"]
    assert shas[str(a)]["backend_sha"] == "backend-B"
    assert shas[str(b)]["backend_sha"] == "backend-OTHER"


# ---- fidelity vs the archive -------------------------------------------------


def _write_archive(tmp_path) -> Path:
    """Archive-shaped run: nvd/gcve stamps only (the real 2026-06 run_meta has
    no osv key), same C1 tree plus an archive-only C2 analysis."""
    return _write_rung(
        tmp_path / "archive",
        [_arow(URL1, C1), _arow(URL2, C2)],
        [_vrow(URL1, C1, "CVE-1", "lodash"),
         _vrow(URL1, C1, "CVE-4", "glob"),
         _vrow(URL2, C2, "CVE-9", "debug")],
        sources={"nvd": "2026-06-29T18:00:00Z", "npm": "0", "gcve": "2026-06-29T18:10:00Z"},
    )


def test_fidelity_compares_nearest_rung_on_shared_keys(rungs, tmp_path):
    archive = _write_archive(tmp_path)
    out = ld.compute(rungs["dirs"], archive_dir=archive)
    f = out["fidelity"]
    assert Path(f["rung_dir"]).name == "rung-fresh"  # within 3d of 2026-06-29
    assert f["shared_analyses"] == 2
    assert f["rung_only_analyses"] == 0
    assert f["archive_only_analyses"] == 0
    # shared-key instances: rung {CVE-1, CVE-3, CVE-9} vs archive {CVE-1, CVE-4, CVE-9}
    assert f["rung_instances"] == 3
    assert f["archive_instances"] == 3
    assert f["instance_jaccard"] == pytest.approx(2 / 4)
    assert f["instance_delta_pct"] == pytest.approx(0.0)


def test_fidelity_skipped_when_no_rung_near_archive_date(tmp_path, caplog):
    a = _write_rung(tmp_path / "a", [_arow(URL1, C1)], [],
                    sources=_osv("2024-01-01T00:00:00Z"))
    archive = _write_archive(tmp_path)
    with caplog.at_level("INFO"):
        out = ld.compute([a], archive_dir=archive)
    assert out["fidelity"] is None
    assert any("fidelity check skipped" in r.message for r in caplog.records)


def test_fidelity_omitted_without_archive(rungs):
    assert rungs["out"]["fidelity"] is None


# ---- output shape ------------------------------------------------------------


def test_epss_rows_and_meta_plumbing(rungs):
    by_name = {Path(r["dir"]).name: r for r in rungs["out"]["rungs"]}
    assert by_name["rung-2023"]["epss_rows"] == 1
    assert by_name["rung-2025"]["epss_rows"] == 5
    assert len(rungs["out"]["meta"]["rung_dirs"]) == 3


def test_output_is_json_serialisable(rungs, tmp_path):
    archive = _write_archive(tmp_path)
    json.dumps(ld.compute(rungs["dirs"], archive_dir=archive))
