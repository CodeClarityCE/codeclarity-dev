from __future__ import annotations

import pandas as pd
import pytest

from js_vuln_study import miner

# ---- classify_fix / classify_removal -----------------------------------------


def test_classify_fix_upgraded_when_non_vulnerable_version_remains():
    kind, to = miner.classify_fix({"yarn.lock": {"lodash": {"4.17.21"}}}, "lodash", {"4.17.15"})
    assert kind == "upgraded" and to == "4.17.21"


def test_classify_fix_removed_when_gone_from_every_lockfile():
    kind, to = miner.classify_fix({"yarn.lock": None, "package-lock.json": {}}, "lodash", {"4.17.15"})
    assert kind == "removed" and to is None


def test_classify_fix_anomalous_when_vulnerable_version_still_present():
    kind, to = miner.classify_fix({"yarn.lock": {"lodash": {"4.17.15"}}}, "lodash", {"4.17.15"})
    assert kind == "anomalous_still_present"


def test_classify_removal_direct_vs_transitive_vs_unknown():
    assert miner.classify_removal({"lodash"}, set(), "lodash") == "removed_direct"
    assert miner.classify_removal(set(), set(), "lodash") == "removed_transitive"
    assert miner.classify_removal(None, set(), "lodash") == "removed"
    assert miner.classify_removal({"lodash"}, {"lodash"}, "lodash") == "removed"  # still declared: inconsistent tree


# ---- locate_fix ---------------------------------------------------------------


def _commits(n: int) -> list[dict]:
    return [{"sha": f"c{i}", "date": f"2024-01-{i + 1:02d}T00:00:00Z"} for i in range(n)]


def test_locate_fix_no_commits_is_not_found():
    assert miner.locate_fix([], lambda sha: (True, None), lambda: (True, None))["status"] == "not_found"


def test_locate_fix_linear_scan_finds_first_absent():
    commits = _commits(4)
    present = {"c0": True, "c1": True, "c2": False, "c3": False}
    r = miner.locate_fix(commits, lambda sha: (present[sha], "yarn.lock"), lambda: (True, "yarn.lock"))
    assert r == {"status": "found", "method": "linear_scan", "lockfile": "yarn.lock", "fix_commit_sha": "c2", "fixed_at": commits[2]["date"]}


def test_locate_fix_linear_scan_fix_at_first_commit_checks_boundary():
    commits = _commits(2)
    present = {"c0": False, "c1": False}
    r = miner.locate_fix(commits, lambda sha: (present[sha], None), lambda: (True, "yarn.lock"))
    assert r["status"] == "found" and r["fix_commit_sha"] == "c0"


def test_locate_fix_boundary_not_present_is_ambiguous_not_in_root_lockfile():
    commits = _commits(2)
    r = miner.locate_fix(commits, lambda sha: (False, None), lambda: (False, None))
    assert r == {"status": "ambiguous", "method": "not_in_root_lockfile", "lockfile": None, "fix_commit_sha": None, "fixed_at": None}


def test_locate_fix_still_present_at_window_end_is_ambiguous():
    commits = _commits(2)
    r = miner.locate_fix(commits, lambda sha: (True, "yarn.lock"), lambda: (True, "yarn.lock"))
    assert r["status"] == "ambiguous" and r["method"] == "still_present_at_window_end"


def test_locate_fix_non_monotonic_reintroduction_detected_in_linear_scan():
    commits = _commits(3)
    present = {"c0": True, "c1": False, "c2": True}  # absent then present again
    r = miner.locate_fix(commits, lambda sha: (present[sha], None), lambda: (True, None))
    assert r["status"] == "ambiguous" and r["method"] == "non_monotonic"


def test_locate_fix_bisection_above_linear_scan_max():
    n = miner.LINEAR_SCAN_MAX + 5
    commits = _commits(n)
    flip = 6  # present for indices < flip, absent from flip onward
    present = {c["sha"]: (i < flip) for i, c in enumerate(commits)}
    calls = []

    def present_at(sha):
        calls.append(sha)
        return present[sha], "pnpm-lock.yaml"

    r = miner.locate_fix(commits, present_at, lambda: (True, "pnpm-lock.yaml"))
    assert r["status"] == "found"
    assert r["method"] == "binary_search"
    assert r["fix_commit_sha"] == commits[flip]["sha"]
    assert len(calls) < n  # bisection probes far fewer than every commit


def test_locate_fix_bisection_reintroduction_blind_spot():
    # A reintroduction the bisection path never probes is NOT detected: the
    # accepted limitation under the monotone-fix assumption.
    n = miner.LINEAR_SCAN_MAX + 3
    commits = _commits(n)
    present = {c["sha"]: (i == 0) for i, c in enumerate(commits)}  # present only at c0
    present[commits[-2]["sha"]] = True  # a reintroduction bisection may skip past
    r = miner.locate_fix(commits, lambda sha: (present[sha], None), lambda: (True, None))
    assert r["status"] in ("found", "ambiguous")  # does not crash; may miss the reintroduction


# ---- derive_units ---------------------------------------------------------------


def _analyses_rows(pid, npm, dates):
    return [{"project_id": pid, "npm_name": npm, "git_url": f"https://github.com/{npm}",
              "snapshot_date": d, "commit_hash": f"sha-{d}", "committed_at": None} for d in dates]


def test_derive_units_groups_event_1_intervals():
    analyses = pd.DataFrame(_analyses_rows("P", "p/proj", ["2024-01-01", "2024-02-01", "2024-03-01"]))
    vulns = pd.DataFrame([
        {"project_id": "P", "snapshot_date": "2024-01-01", "vulnerability_id": "CVE-X",
         "affected_dependency": "lodash", "affected_version": "4.17.15", "severity_class": "HIGH"},
    ])
    units, counters = miner.derive_units(vulns, analyses)
    assert counters["units"] == 1
    assert units[0].dependency == "lodash"
    assert units[0].versions == ("4.17.15",)
    assert units[0].last_seen == "2024-01-01"
    assert units[0].next_snapshot == "2024-02-01"


def test_derive_units_skips_intervals_with_no_version_info():
    analyses = pd.DataFrame(_analyses_rows("P", "p/proj", ["2024-01-01", "2024-02-01"]))
    vulns = pd.DataFrame([
        {"project_id": "P", "snapshot_date": "2024-01-01", "vulnerability_id": "CVE-X",
         "affected_dependency": "lodash", "affected_version": None, "severity_class": "HIGH"},
    ])
    units, counters = miner.derive_units(vulns, analyses)
    assert counters["units"] == 0
    assert counters["skipped_no_version"] == 1
