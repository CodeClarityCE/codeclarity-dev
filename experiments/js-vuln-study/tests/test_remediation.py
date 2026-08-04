"""Unit tests for the day-resolution remediation-lag miner.

All GitHub traffic is served by httpx.MockTransport — no network. The fix
search (`locate_fix`) is exercised purely offline through synthetic probe
callbacks; the miner end-to-end test drives `run_mining` against fixture
parquet tables plus mocked commit-list/raw-blob endpoints. Run with:
cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import remediation, stats  # noqa: E402
from js_vuln_study.remediation import (  # noqa: E402
    MiningUnit,
    derive_units,
    estimate_request_budget,
    list_lockfile_commits,
    locate_fix,
    lockfile_versions_at,
    run_mining,
)

GIT_URL = "https://github.com/owner1/repo1"

YARN_VULNERABLE = b'# yarn lockfile v1\nlodash@^4.17.15:\n  version "4.17.20"\n'
YARN_FIXED = b'# yarn lockfile v1\nlodash@^4.17.15:\n  version "4.17.21"\n'


def gh_commit(sha: str, date: str) -> dict:
    return {"sha": sha, "commit": {"committer": {"date": date}}}


def make_tables(tmp_path: Path) -> Path:
    """Fixture parquet tables: one project, three completed snapshots,
    CVE-X/lodash@4.17.20 present at the first two -> one event=1 interval
    with last_seen 2024-04-01 and the fix window ending at 2024-07-01."""
    analyses = pd.DataFrame([
        {"project_id": "p1", "npm_name": "owner1/repo1", "git_url": GIT_URL,
         "snapshot_date": d, "commit_hash": sha, "committed_at": at}
        for d, sha, at in [
            ("2024-01-01", "snap1", "2023-12-30T10:00:00Z"),
            ("2024-04-01", "snap2", "2024-03-30T10:00:00Z"),
            ("2024-07-01", "snap3", "2024-06-29T10:00:00Z"),
        ]
    ])
    vulns = pd.DataFrame([
        {"project_id": "p1", "npm_name": "owner1/repo1", "snapshot_date": d,
         "vulnerability_id": "CVE-X", "affected_dependency": "lodash",
         "affected_version": "4.17.20", "severity_class": "HIGH"}
        for d in ("2024-01-01", "2024-04-01")
    ])
    tables = tmp_path / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    analyses.to_parquet(tables / "analyses.parquet", index=False)
    vulns.to_parquet(tables / "vulns.parquet", index=False)
    return tmp_path


# ---- unit derivation --------------------------------------------------------


def test_derive_units_from_fixture_tables(tmp_path):
    data_dir = make_tables(tmp_path)
    analyses = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    vulns = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
    units, counters = derive_units(vulns, analyses)
    assert counters == {
        "intervals": 1, "event_intervals": 1, "units": 1, "skipped_no_version": 0,
    }
    (u,) = units
    assert u.dependency == "lodash"
    assert u.versions == ("4.17.20",)
    assert u.last_seen == "2024-04-01"
    assert u.next_snapshot == "2024-07-01"
    # window bounds come from the boundary snapshots' committed_at
    assert u.since == "2024-03-30T10:00:00Z"
    assert u.until == "2024-06-29T10:00:00Z"
    assert u.boundary_sha == "snap2"
    assert u.n_intervals == 1


def test_derive_units_groups_cves_and_splits_version_sets(tmp_path):
    data_dir = make_tables(tmp_path)
    analyses = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    vulns = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
    extra = pd.DataFrame([
        # CVE-Y: same dep, same version set, same window -> merges into the unit
        {"project_id": "p1", "npm_name": "owner1/repo1", "snapshot_date": d,
         "vulnerability_id": "CVE-Y", "affected_dependency": "lodash",
         "affected_version": "4.17.20", "severity_class": "LOW"}
        for d in ("2024-01-01", "2024-04-01")
    ] + [
        # CVE-Z: same dep but a different vulnerable version -> its own unit
        {"project_id": "p1", "npm_name": "owner1/repo1", "snapshot_date": d,
         "vulnerability_id": "CVE-Z", "affected_dependency": "lodash",
         "affected_version": "3.10.1", "severity_class": "HIGH"}
        for d in ("2024-01-01", "2024-04-01")
    ])
    units, counters = derive_units(pd.concat([vulns, extra], ignore_index=True), analyses)
    assert counters["event_intervals"] == 3
    assert counters["units"] == 2
    by_versions = {u.versions: u for u in units}
    assert by_versions[("4.17.20",)].n_intervals == 2
    assert by_versions[("3.10.1",)].n_intervals == 1


def test_derive_units_skips_intervals_without_version_info(tmp_path):
    data_dir = make_tables(tmp_path)
    analyses = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    vulns = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
    vulns["affected_version"] = None
    units, counters = derive_units(vulns, analyses)
    assert units == []
    assert counters["skipped_no_version"] == 1


def test_estimate_request_budget_shape():
    unit = MiningUnit(
        npm_name="owner1/repo1", project_id="p1", git_url=GIT_URL,
        dependency="lodash", versions=("4.17.20",), last_seen="2024-04-01",
        next_snapshot="2024-07-01", since="s", until="u", boundary_sha="snap2",
    )
    budget = estimate_request_budget([unit])
    assert budget["units"] == 1
    assert budget["distinct_windows"] == 1
    assert budget["commit_list_calls"] == 3  # one per root lockfile name


# ---- fix-commit search ------------------------------------------------------


def _commits(n: int) -> list[dict]:
    return [{"sha": f"c{i}", "date": f"2024-05-{i + 1:02d}T00:00:00Z"} for i in range(n)]


def _probe(present: list[bool]):
    calls: list[str] = []

    def present_at(sha: str):
        calls.append(sha)
        p = present[int(sha[1:])]
        return p, ("yarn.lock" if p else None)

    return present_at, calls


def test_locate_fix_empty_window_is_not_found():
    got = locate_fix([], None, None)
    assert (got["status"], got["method"]) == ("not_found", "no_lockfile_commits")


def test_locate_fix_linear_monotonic():
    present_at, _ = _probe([True, True, False, False])
    got = locate_fix(_commits(4), present_at, lambda: (True, "yarn.lock"))
    assert got["status"] == "found"
    assert got["method"] == "linear_scan"
    assert got["fix_commit_sha"] == "c2"
    assert got["fixed_at"] == "2024-05-03T00:00:00Z"
    assert got["lockfile"] == "yarn.lock"


def test_locate_fix_linear_non_monotonic_is_ambiguous():
    present_at, _ = _probe([True, False, True, False])
    got = locate_fix(_commits(4), present_at, lambda: (True, "yarn.lock"))
    assert (got["status"], got["method"]) == ("ambiguous", "non_monotonic")
    assert got["fix_commit_sha"] is None


def test_locate_fix_still_present_at_window_end():
    present_at, _ = _probe([True, True, True])
    got = locate_fix(_commits(3), present_at, lambda: (True, "yarn.lock"))
    assert (got["status"], got["method"]) == ("ambiguous", "still_present_at_window_end")


def test_locate_fix_absent_everywhere_with_boundary_presence():
    # Version gone at the first lockfile commit already: the fix IS that
    # commit, provided the boundary snapshot commit still carried the version.
    present_at, _ = _probe([False, False])
    got = locate_fix(_commits(2), present_at, lambda: (True, "yarn.lock"))
    assert got["status"] == "found"
    assert got["fix_commit_sha"] == "c0"
    assert got["lockfile"] == "yarn.lock"


def test_locate_fix_never_in_root_lockfile_is_ambiguous():
    present_at, _ = _probe([False, False])
    got = locate_fix(_commits(2), present_at, lambda: (False, None))
    assert (got["status"], got["method"]) == ("ambiguous", "not_in_root_lockfile")


def test_locate_fix_binary_search_on_large_window():
    n = 32  # well above LINEAR_SCAN_MAX
    present_at, calls = _probe([i < 21 for i in range(n)])
    got = locate_fix(_commits(n), present_at, lambda: (True, "yarn.lock"))
    assert got["status"] == "found"
    assert got["method"] == "binary_search"
    assert got["fix_commit_sha"] == "c21"
    # log2 probing, not a full scan
    assert len(calls) <= 8


def test_locate_fix_binary_search_absent_everywhere_checks_boundary():
    n = 10
    boundary = {"asked": False}

    def boundary_present():
        boundary["asked"] = True
        return True, "pnpm-lock.yaml"

    present_at, _ = _probe([False] * n)
    got = locate_fix(_commits(n), present_at, boundary_present)
    assert boundary["asked"]
    assert got["status"] == "found"
    assert got["fix_commit_sha"] == "c0"
    assert got["lockfile"] == "pnpm-lock.yaml"


# ---- cached GitHub access ---------------------------------------------------


def test_list_lockfile_commits_paginates_and_caches(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        page = int(request.url.params["page"])
        if page == 1:
            return httpx.Response(200, json=[
                gh_commit(f"s{i}", f"2024-04-01T{i % 24:02d}:{i % 60:02d}:00Z")
                for i in range(100)
            ])
        return httpx.Response(200, json=[gh_commit("last", "2024-06-01T00:00:00Z")])

    http = httpx.Client(base_url="https://gh.test", transport=httpx.MockTransport(handler))
    got = list_lockfile_commits(http, tmp_path, "owner1/repo1", "yarn.lock", "a", "b")
    assert len(got) == 101
    assert got == sorted(got, key=lambda c: (c["date"], c["sha"]))
    assert len(calls) == 2  # two pages
    again = list_lockfile_commits(http, tmp_path, "owner1/repo1", "yarn.lock", "a", "b")
    assert again == got
    assert len(calls) == 2  # served from cache, no new HTTP


def test_lockfile_versions_at_caches_parsed_and_missing(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("yarn.lock"):
            return httpx.Response(200, content=YARN_VULNERABLE)
        return httpx.Response(404)

    http = httpx.Client(base_url="https://raw.test", transport=httpx.MockTransport(handler))
    status, versions = lockfile_versions_at(http, tmp_path, "owner1/repo1", "c1", "yarn.lock")
    assert status == "parsed"
    assert versions == {"lodash": {"4.17.20"}}
    status, versions = lockfile_versions_at(http, tmp_path, "owner1/repo1", "c1", "pnpm-lock.yaml")
    assert (status, versions) == ("missing", None)
    n_calls = len(calls)
    # both outcomes are cache hits on re-query
    assert lockfile_versions_at(http, tmp_path, "owner1/repo1", "c1", "yarn.lock")[0] == "parsed"
    assert lockfile_versions_at(http, tmp_path, "owner1/repo1", "c1", "pnpm-lock.yaml")[0] == "missing"
    assert len(calls) == n_calls


# ---- merge_day_resolution ---------------------------------------------------


def _interval(project="p1", dep="lodash", first="2024-01-01", last="2024-04-01",
              duration=182, event=1, sev="HIGH"):
    return {
        "project_id": project, "npm_name": "owner1/repo1",
        "vulnerability_id": "CVE-X", "affected_dependency": dep,
        "severity_class": sev, "first_seen": pd.Timestamp(first),
        "last_seen": pd.Timestamp(last), "duration_days": duration, "event": event,
    }


def _event(project="p1", dep="lodash", last="2024-04-01", status="found",
           fixed_at="2024-04-20T12:00:00Z"):
    return {
        "npm_name": "owner1/repo1", "project_id": project,
        "affected_dependency": dep, "affected_version": "4.17.20",
        "workspace_scope": "root", "last_seen": last, "next_snapshot": "2024-07-01",
        "lockfile": "yarn.lock", "fix_commit_sha": "c2", "fixed_at": fixed_at,
        "method": "binary_search", "status": status,
    }


def test_merge_day_resolution_rewrites_matched_event_intervals():
    ints = pd.DataFrame([_interval(), _interval(dep="semver", event=0, duration=91)])
    got = stats.merge_day_resolution(ints, pd.DataFrame([_event()]))
    day = got[got["affected_dependency"] == "lodash"].iloc[0]
    assert day["resolution"] == "day"
    assert day["duration_days"] == 110  # 2024-01-01 -> 2024-04-20
    assert not day["excluded"]
    other = got[got["affected_dependency"] == "semver"].iloc[0]
    assert other["resolution"] == "quarter"
    assert other["duration_days"] == 91  # censored rows untouched


def test_merge_day_resolution_ambiguous_flags_excluded():
    got = stats.merge_day_resolution(
        pd.DataFrame([_interval()]),
        pd.DataFrame([_event(status="ambiguous", fixed_at=None)]),
    )
    row = got.iloc[0]
    assert row["excluded"]
    assert row["resolution"] == "quarter"
    assert row["duration_days"] == 182


def test_merge_day_resolution_latest_found_wins():
    events = pd.DataFrame([
        _event(fixed_at="2024-04-10T00:00:00Z"),
        _event(fixed_at="2024-05-05T00:00:00Z"),
    ])
    got = stats.merge_day_resolution(pd.DataFrame([_interval()]), events)
    assert got.iloc[0]["duration_days"] == 125  # 2024-01-01 -> 2024-05-05


def test_merge_day_resolution_ignores_fix_before_first_seen():
    got = stats.merge_day_resolution(
        pd.DataFrame([_interval(first="2024-04-01", last="2024-04-01", duration=91)]),
        pd.DataFrame([_event(fixed_at="2024-03-20T00:00:00Z", last="2024-04-01")]),
    )
    row = got.iloc[0]
    assert row["resolution"] == "quarter"
    assert row["duration_days"] == 91


def test_merge_day_resolution_no_events_is_identity_plus_columns():
    ints = pd.DataFrame([_interval()])
    got = stats.merge_day_resolution(ints, pd.DataFrame())
    assert list(got["resolution"]) == ["quarter"]
    assert list(got["excluded"]) == [False]


# ---- end-to-end mining ------------------------------------------------------


@pytest.fixture()
def mocked_github():
    """(api_client, raw_client, calls): yarn.lock changed twice inside the
    window — c1 still vulnerable, c2 upgraded — other lockfiles absent."""
    calls = {"api": 0, "raw": 0}
    blobs = {"snap2": YARN_VULNERABLE, "c1": YARN_VULNERABLE, "c2": YARN_FIXED}

    def api_handler(request: httpx.Request) -> httpx.Response:
        calls["api"] += 1
        assert request.url.path == "/repos/owner1/repo1/commits"
        if request.url.params["path"] == "yarn.lock":
            return httpx.Response(200, json=[
                gh_commit("c1", "2024-04-15T00:00:00Z"),
                gh_commit("c2", "2024-05-01T00:00:00Z"),
            ])
        return httpx.Response(200, json=[])

    def raw_handler(request: httpx.Request) -> httpx.Response:
        calls["raw"] += 1
        _, _, _, sha, name = request.url.path.split("/")
        if name == "yarn.lock" and sha in blobs:
            return httpx.Response(200, content=blobs[sha])
        return httpx.Response(404)

    api = httpx.Client(base_url="https://gh.test", transport=httpx.MockTransport(api_handler))
    raw = httpx.Client(base_url="https://raw.test", transport=httpx.MockTransport(raw_handler))
    yield api, raw, calls
    api.close()
    raw.close()


def test_run_mining_dry_run_touches_nothing(tmp_path, capsys):
    data_dir = make_tables(tmp_path)
    out = data_dir / "tables" / "remediation_events.parquet"
    assert run_mining(data_dir, out=out, dry_run=True) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counters"]["units"] == 1
    assert report["budget"]["commit_list_calls"] == 3
    assert not out.exists()
    assert not (data_dir / "mining_cache").exists()


def test_run_mining_end_to_end_and_resume(tmp_path, mocked_github):
    api, raw, calls = mocked_github
    data_dir = make_tables(tmp_path)
    out = data_dir / "tables" / "remediation_events.parquet"
    assert run_mining(data_dir, out=out, http_api=api, http_raw=raw) == 0

    df = pd.read_parquet(out)
    assert len(df) == 1
    row = df.iloc[0]
    assert row["status"] == "found"
    assert row["method"] == "linear_scan"  # 2-commit window
    assert row["fix_commit_sha"] == "c2"
    assert row["fixed_at"] == "2024-05-01T00:00:00Z"
    assert row["lockfile"] == "yarn.lock"
    assert row["workspace_scope"] == "root"
    assert row["affected_version"] == "4.17.20"
    assert (row["last_seen"], row["next_snapshot"]) == ("2024-04-01", "2024-07-01")
    assert calls["api"] == 3  # one commit-list call per lockfile name

    # the mined event feeds straight back into the survival intervals
    analyses = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    vulns = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
    merged = stats.merge_day_resolution(stats.presence_intervals(vulns, analyses), df)
    assert list(merged["resolution"]) == ["day"]
    assert merged.iloc[0]["duration_days"] == (pd.Timestamp("2024-05-01")
                                               - pd.Timestamp("2024-01-01")).days

    # resumability: a second invocation replays results.jsonl, no new HTTP
    before = dict(calls)
    assert run_mining(data_dir, out=out, http_api=api, http_raw=raw) == 0
    assert calls == before
    assert len(pd.read_parquet(out)) == 1
