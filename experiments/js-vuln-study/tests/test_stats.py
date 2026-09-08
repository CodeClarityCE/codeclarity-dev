"""Unit tests for the shared statistics helpers.

Everything here is pure numpy/pandas on hand-built frames, no API, no
network. The presence-interval tests encode the worked example from the
`js_vuln_study.stats` module docstring. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from js_vuln_study import stats


# ---- gini / lorenz ----------------------------------------------------------


def test_gini_all_equal_is_zero():
    assert stats.gini([5, 5, 5, 5]) == pytest.approx(0.0, abs=1e-9)


def test_gini_single_holder_is_n_minus_1_over_n():
    assert stats.gini([0, 0, 0, 10]) == pytest.approx(3 / 4)


def test_gini_empty_and_all_zero_are_nan():
    assert math.isnan(stats.gini([]))
    assert math.isnan(stats.gini([0, 0, 0]))


def test_gini_ignores_nans():
    assert stats.gini([5, np.nan, 5, 5]) == pytest.approx(0.0, abs=1e-9)


def test_lorenz_monotone_with_unit_endpoints():
    pop, val = stats.lorenz([4, 1, 3, 2])
    assert (pop[0], val[0]) == (0.0, 0.0)
    assert (pop[-1], val[-1]) == (1.0, 1.0)
    assert np.all(np.diff(val) >= 0)
    assert np.all(np.diff(pop) >= 0)
    # hand-check: sorted cum shares of [1,2,3,4] over total 10
    assert val == pytest.approx([0.0, 0.1, 0.3, 0.6, 1.0])


# ---- pkgs_to_clear ------------------------------------------------------------


def test_pkgs_to_clear_toy_distribution():
    counts = [10, 50, 10, 30]  # sorted desc: cum shares 0.5, 0.8, 0.9, 1.0
    assert stats.pkgs_to_clear(counts, 0.8) == 2
    assert stats.pkgs_to_clear(counts, 0.9) == 3
    assert stats.pkgs_to_clear(counts, 1.0) == 4


def test_pkgs_to_clear_exact_boundary_hit():
    # The top package holds exactly 50%: share=0.5 is met by 1 package.
    assert stats.pkgs_to_clear([50, 30, 10, 10], 0.5) == 1


def test_pkgs_to_clear_empty_or_zero_is_zero():
    assert stats.pkgs_to_clear([], 0.5) == 0
    assert stats.pkgs_to_clear([0, 0], 0.5) == 0


# ---- headline -----------------------------------------------------------------


def _vuln(project, dep, sev, vuln_id, **over) -> dict:
    rec = {
        "project_id": project,
        "vulnerability_id": vuln_id,
        "affected_dependency": dep,
        "severity_class": sev,
        "conflict_flag": "MATCH_CORRECT",
        "withdrawn_date": None,
        "direct_dependency": True,
    }
    rec.update(over)
    return rec


@pytest.fixture
def head_pair():
    """4-project universe (2 clean), 4 in-universe vulns + 1 ghost row."""
    analyses = pd.DataFrame({"project_id": ["p1", "p2", "p3", "p4"]})
    vulns = pd.DataFrame([
        _vuln("p1", "lodash", "CRITICAL", "CVE-1"),
        _vuln("p1", "lodash", "HIGH", "CVE-2"),
        _vuln("p1", "tar", "MEDIUM", "CVE-3"),
        _vuln("p2", "lodash", "CRITICAL", "CVE-1"),
        # outside the analyses universe, must be dropped everywhere
        _vuln("ghost", "evil", "HIGH", "CVE-9"),
    ])
    return vulns, analyses


def test_headline_has_every_documented_key(head_pair):
    h = stats.headline(*head_pair)
    for key in [*stats.HEADLINE_SCALAR_KEYS, "sev_counts", "top_packages"]:
        assert key in h, key


def test_headline_hand_computed_values(head_pair):
    h = stats.headline(*head_pair)
    assert h["n_projects"] == 4
    assert h["n_affected"] == 2
    assert h["affected_share"] == pytest.approx(0.5)
    assert h["instances"] == 4  # the ghost-project row is excluded
    assert h["distinct_vuln_packages"] == 2
    # loads zero-filled over the universe: [3, 1, 0, 0]
    assert h["load_median"] == pytest.approx(0.5)
    assert h["load_mean"] == pytest.approx(1.0)
    assert h["load_max"] == pytest.approx(3.0)
    assert h["sev_counts"] == {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "NONE": 0}
    assert h["high_critical_share"] == pytest.approx(3 / 4)
    # only 2 packages / 4 projects, so the top-10 covers everything
    assert h["top10_pkg_share"] == pytest.approx(1.0)
    assert h["top10_proj_share"] == pytest.approx(1.0)
    # pkg counts lodash=3, tar=1 -> cum shares 0.75, 1.0
    assert h["pkgs_clear_50"] == 1
    assert h["pkgs_clear_80"] == 2
    assert h["pkgs_clear_90"] == 2
    assert h["gini_pkg"] == pytest.approx(0.25)          # gini([3, 1])
    assert h["gini_proj"] == pytest.approx(0.625)        # gini([3, 1, 0, 0])
    # spread: lodash hits {p1, p2}, tar hits {p1}
    assert h["top_packages"] == [("lodash", 2), ("tar", 1)]


def test_headline_zero_vuln_projects_count_in_universe():
    analyses = pd.DataFrame({"project_id": ["p1", "p2"]})
    vulns = pd.DataFrame(
        columns=["project_id", "vulnerability_id", "affected_dependency", "severity_class"]
    )
    h = stats.headline(vulns, analyses)
    assert h["n_projects"] == 2
    assert h["n_affected"] == 0
    assert h["instances"] == 0
    assert h["load_median"] == 0.0 and h["load_max"] == 0.0
    assert h["pkgs_clear_50"] == 0
    assert math.isnan(h["high_critical_share"])


# ---- sensitivity_sweep ----------------------------------------------------------


def test_sensitivity_sweep_subsets():
    analyses = pd.DataFrame({"project_id": ["p1", "p2"]})
    vulns = pd.DataFrame([
        _vuln("p1", "lodash", "HIGH", "CVE-1",
              conflict_flag="MATCH_CORRECT", withdrawn_date=None, direct_dependency=True),
        _vuln("p1", "tar", "LOW", "CVE-2",
              conflict_flag="MATCH_POSSIBLE_INCORRECT", withdrawn_date="", direct_dependency=False),
        _vuln("p2", "glob", "MEDIUM", "CVE-3",
              conflict_flag=None, withdrawn_date="2024-01-01T00:00:00Z", direct_dependency=True),
        _vuln("p2", "semver", "CRITICAL", "CVE-4",
              conflict_flag="MATCH_CORRECT", withdrawn_date=None, direct_dependency=False),
    ])
    df = stats.sensitivity_sweep(vulns, analyses)
    assert list(df["subset"]) == ["all", "match_correct_only", "non_withdrawn", "direct_only"]
    assert set(df.columns) == {"subset", *stats.HEADLINE_SCALAR_KEYS}
    by = df.set_index("subset")
    assert by.loc["all", "instances"] == 4
    # anything != MATCH_CORRECT (including null) is excluded
    assert by.loc["match_correct_only", "instances"] == 2
    # only the non-null, non-empty withdrawn_date row is excluded
    assert by.loc["non_withdrawn", "instances"] == 3
    assert by.loc["direct_only", "instances"] == 2
    # the project universe is fixed across subsets
    assert set(by["n_projects"]) == {2}


# ---- presence_intervals -----------------------------------------------------------


def _snap_rows(pid, npm, dates, committed=None) -> list[dict]:
    return [
        {"project_id": pid, "npm_name": npm, "snapshot_date": d,
         "committed_at": committed if d == "HEAD" else None}
        for d in dates
    ]


def _pres(pid, date, vid, dep, sev="HIGH") -> dict:
    return {"project_id": pid, "snapshot_date": date, "vulnerability_id": vid,
            "affected_dependency": dep, "severity_class": sev}


def test_presence_intervals_worked_example():
    """The exact scenario from the stats.py module docstring."""
    analyses = pd.DataFrame(
        _snap_rows("P", "p-proj", ["2024-01-01", "2024-04-01", "2024-07-01"])
        + _snap_rows("Q", "q-proj", ["2024-01-01", "2024-07-01"])
    )
    vulns = pd.DataFrame([
        _pres("P", "2024-01-01", "CVE-X", "lodash"),
        _pres("P", "2024-01-01", "CVE-Y", "tar"),
        _pres("P", "2024-04-01", "CVE-Y", "tar"),
        _pres("P", "2024-07-01", "CVE-Y", "tar"),
        _pres("P", "2024-01-01", "CVE-Z", "glob"),
        _pres("P", "2024-07-01", "CVE-Z", "glob"),
        _pres("Q", "2024-01-01", "CVE-W", "semver"),
    ])
    df = stats.presence_intervals(vulns, analyses)
    assert len(df) == 5

    def rows(vid):
        return df[df["vulnerability_id"] == vid].sort_values("first_seen")

    # CVE-X/lodash: gone at 04-01 -> fixed, duration runs to the next snapshot
    x = rows("CVE-X").iloc[0]
    assert x["first_seen"] == x["last_seen"] == pd.Timestamp("2024-01-01")
    assert (int(x["event"]), int(x["duration_days"])) == (1, 91)
    assert x["npm_name"] == "p-proj" and x["severity_class"] == "HIGH"

    # CVE-Y/tar: present throughout -> one censored interval
    y = rows("CVE-Y").iloc[0]
    assert y["first_seen"] == pd.Timestamp("2024-01-01")
    assert y["last_seen"] == pd.Timestamp("2024-07-01")
    assert (int(y["event"]), int(y["duration_days"])) == (0, 182)

    # CVE-Z/glob: reappears after an observed absence -> two intervals
    z = rows("CVE-Z")
    assert len(z) == 2
    assert [int(e) for e in z["event"]] == [1, 0]
    assert [int(d) for d in z["duration_days"]] == [91, 0]
    assert z.iloc[1]["first_seen"] == pd.Timestamp("2024-07-01")

    # CVE-W/semver (Q): the missed 04-01 grid date censors the run at 0 d
    w = rows("CVE-W").iloc[0]
    assert w["project_id"] == "Q"
    assert (int(w["event"]), int(w["duration_days"])) == (0, 0)


def test_presence_intervals_head_row_placed_at_committed_at():
    analyses = pd.DataFrame(
        _snap_rows("H", "h-proj", ["2024-01-01"])
        + _snap_rows("H", "h-proj", ["HEAD"], committed="2024-03-15T12:34:56Z")
    )
    vulns = pd.DataFrame([
        _pres("H", "2024-01-01", "CVE-A", "left-pad"),  # fixed by HEAD
        _pres("H", "2024-01-01", "CVE-B", "chalk"),     # still present at HEAD
        _pres("H", "HEAD", "CVE-B", "chalk"),
    ])
    df = stats.presence_intervals(vulns, analyses).set_index("vulnerability_id")
    a = df.loc["CVE-A"]
    assert int(a["event"]) == 1
    assert int(a["duration_days"]) == 74  # 2024-01-01 -> 2024-03-15
    b = df.loc["CVE-B"]
    assert int(b["event"]) == 0
    assert b["last_seen"] == pd.Timestamp("2024-03-15")  # committed_at, normalised
    assert int(b["duration_days"]) == 74


def test_presence_intervals_single_snapshot_yields_nothing():
    analyses = pd.DataFrame(_snap_rows("S", "s-proj", ["2024-01-01"]))
    vulns = pd.DataFrame([_pres("S", "2024-01-01", "CVE-A", "x")])
    df = stats.presence_intervals(vulns, analyses)
    assert df.empty
    assert list(df.columns) == stats._INTERVAL_COLS


def test_presence_intervals_reappearing_pair_yields_two_intervals():
    analyses = pd.DataFrame(
        _snap_rows("R", "r-proj", ["2024-01-01", "2024-02-01", "2024-03-01"])
    )
    vulns = pd.DataFrame([
        _pres("R", "2024-01-01", "CVE-A", "x"),
        _pres("R", "2024-03-01", "CVE-A", "x"),
    ])
    df = stats.presence_intervals(vulns, analyses)
    assert len(df) == 2
    assert [int(e) for e in df["event"]] == [1, 0]
    assert [int(d) for d in df["duration_days"]] == [31, 0]
    assert df.iloc[1]["first_seen"] == pd.Timestamp("2024-03-01")


def test_presence_intervals_monthly_grid_shortens_duration_vs_quarterly_only():
    """Adding monthly 2024+ dates on top of the pre-2024 quarterly grid is
    additive: the same fix, observed through the fuller monthly grid, is
    bracketed into a much shorter (truer) window than a quarterly-only grid
    would have reported it in. This is the whole point of the grid change,
    since quarterly presence detection cannot see a sub-quarter fix."""
    monthly = pd.DataFrame(_snap_rows(
        "M", "m-proj",
        ["2023-10-01", "2024-01-01", "2024-02-01", "2024-03-01", "2024-04-01"],
    ))
    quarterly_only = pd.DataFrame(_snap_rows(
        "M", "m-proj", ["2023-10-01", "2024-01-01", "2024-04-01"],
    ))
    vulns = pd.DataFrame([
        _pres("M", "2023-10-01", "CVE-FAST", "left-pad"),
        _pres("M", "2024-01-01", "CVE-FAST", "left-pad"),
        # absent from 2024-02-01 onward in the monthly view; the quarterly
        # view has no 02-01/03-01 rows at all, so it can't see that.
    ])
    fast_monthly = stats.presence_intervals(vulns, monthly).set_index("vulnerability_id").loc["CVE-FAST"]
    fast_quarterly = stats.presence_intervals(vulns, quarterly_only).set_index("vulnerability_id").loc["CVE-FAST"]
    assert int(fast_monthly["event"]) == int(fast_quarterly["event"]) == 1
    assert int(fast_monthly["duration_days"]) == 123   # 2023-10-01 -> 2024-02-01
    assert int(fast_quarterly["duration_days"]) == 183  # 2023-10-01 -> 2024-04-01 (2024 is a leap year)
    assert fast_monthly["duration_days"] < fast_quarterly["duration_days"]


def test_presence_intervals_missing_monthly_snapshot_censors_via_gap():
    # The grid is derived from ALL projects' dated snapshots: project O
    # supplies 2024-03-01 (making it part of the global grid) while project G
    # skipped that one run: a genuine coverage gap for G specifically, not
    # merely an unobserved date nobody has.
    analyses = pd.DataFrame(
        _snap_rows("G", "g-proj", ["2024-01-01", "2024-02-01", "2024-04-01"])
        + _snap_rows("O", "o-proj", ["2024-01-01", "2024-02-01", "2024-03-01", "2024-04-01"])
    )
    vulns = pd.DataFrame([
        _pres("G", "2024-01-01", "CVE-GAP", "x"),
        _pres("G", "2024-02-01", "CVE-GAP", "x"),
        # absent at 2024-04-01, but the missed 03-01 run means the true fix
        # window is unobserved, not confirmed absent right after 02-01.
    ])
    df = stats.presence_intervals(vulns, analyses).set_index("vulnerability_id")
    gap = df.loc["CVE-GAP"]
    assert int(gap["event"]) == 0  # censored, not counted as fixed at 02-01
    assert gap["last_seen"] == pd.Timestamp("2024-02-01")


def test_presence_intervals_empty_inputs():
    empty_v = pd.DataFrame(columns=[
        "project_id", "snapshot_date", "vulnerability_id",
        "affected_dependency", "severity_class",
    ])
    empty_a = pd.DataFrame(columns=["project_id", "npm_name", "snapshot_date", "committed_at"])
    df = stats.presence_intervals(empty_v, empty_a)
    assert df.empty
    assert list(df.columns) == stats._INTERVAL_COLS


# ---- km_curve / km_median ------------------------------------------------------


def test_km_curve_all_events():
    times, surv = stats.km_curve([1, 2, 3], [1, 1, 1])
    assert list(times) == [0.0, 1.0, 2.0, 3.0]
    assert surv == pytest.approx([1.0, 2 / 3, 1 / 3, 0.0])
    assert stats.km_median(times, surv) == 2.0


def test_km_curve_censoring_shrinks_risk_set():
    # censored at 2 leaves 3 at risk for the t=2 event: 3/4 * 2/3 = 1/2
    times, surv = stats.km_curve([1, 2, 2, 3], [1, 0, 1, 0])
    assert list(times) == [0.0, 1.0, 2.0]
    assert surv == pytest.approx([1.0, 0.75, 0.5])
    assert stats.km_median(times, surv) == 2.0  # boundary: <= 0.5 counts


def test_km_curve_censored_only_is_flat_with_nan_median():
    times, surv = stats.km_curve([5, 10], [0, 0])
    assert list(times) == [0.0]
    assert list(surv) == [1.0]
    assert math.isnan(stats.km_median(times, surv))
