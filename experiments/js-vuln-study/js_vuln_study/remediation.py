"""Day-resolution remediation-lag miner (RQ-G refinement).

`stats.presence_intervals` observes projects quarterly, so an event=1 (fixed)
interval only brackets the true fix inside a ~90-day window between the last
snapshot where the (CVE, package) pair was present and the next completed
snapshot where it was gone. This module mines each repo's git history for the
exact commit in that window where the vulnerable resolved version left the
ROOT lockfile, giving a day-resolution `fixed_at` that
`stats.merge_day_resolution` folds back into the intervals.

Method, per mining unit — event=1 intervals grouped on (npm_name,
affected_dependency, vulnerable-version-set, boundary window), so CVEs fixed
by the same lockfile change are mined once:

  1. list the commits touching any root lockfile name (`ROOT_LOCKFILES` from
     `lockfiles.py`, the js-sbom list) inside the window via
     `GET /repos/{slug}/commits?path=<lockfile>&since&until` (union across
     the three names, so lockfile migrations mid-window are survivable);
  2. search the chronologically sorted commits for the first one at which NO
     occurrence of any vulnerable resolved version of the package remains in
     any root lockfile (all-occurrences rule; raw-blob fetch +
     `lockfiles.parse_lockfile` per probe);
  3. that commit's committer date is `fixed_at`.

Monotonicity rule: windows with <= LINEAR_SCAN_MAX candidate commits are
scanned linearly, which detects reintroductions exactly (any absent->present
step => status='ambiguous', method='non_monotonic'). Larger windows are
bisected under the monotone-fix assumption — the bisection keeps a
present-below/absent-above invariant at every probe, so it always returns a
genuine present->absent transition, but a reintroduction it never probes
cannot be detected (accepted limitation, recorded as method='binary_search').
When even the first candidate commit lacks the version, the last-seen
snapshot commit itself is probed: version present there => the fix is the
first candidate commit; absent there too => the root lockfile never carried
it (workspace-local lockfile) => 'ambiguous'/'not_in_root_lockfile'. A window
whose last commit still carries the version => 'ambiguous'/
'still_present_at_window_end' (the snapshot-observed fix did not come from a
root-lockfile change). No lockfile-touching commits at all => 'not_found'/
'no_lockfile_commits'.

A `classify_fix` "removed" verdict (the dependency left every root lockfile)
is further split by `classify_removal` into 'removed_direct' (declared in the
root package.json at the boundary commit, no longer declared at the fix
commit — a deliberate drop) vs 'removed_transitive' (never a direct
dependency at the boundary — it left the tree because a parent was
upgraded). Either package.json being unreadable keeps the unsplit 'removed'
value.

Endpoints/auth reuse the existing idioms: `snapshots.GITHUB_API` +
`triangulate.RAW_GITHUB` bases, `_auth_headers`, `_fetch`, and
`_handle_rate_limit` backoff. Everything fetched is cached under
{data_dir}/mining_cache/ (commit lists keyed (slug, lockfile, since, until);
parsed blobs keyed (slug, sha, lockfile)); per-unit results append to
mining_cache/results.jsonl, so an interrupted mine resumes where it stopped.
Only the commit-list calls count against the 5000/h core API budget — raw
blob fetches go to `GH_RAW_BASE`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pandas as pd
from tqdm import tqdm

from .lockfiles import ROOT_LOCKFILES, LockfileParseError, parse_lockfile
from .snapshots import GITHUB_API, _auth_headers as _gh_headers, _handle_rate_limit
from .stats import presence_intervals
from .triangulate import RAW_GITHUB, _fetch, parse_owner_repo

log = logging.getLogger(__name__)

# Windows at most this many candidate commits are scanned linearly (exact
# non-monotonicity detection); larger windows are bisected.
LINEAR_SCAN_MAX = 6
# Assumed candidate commits per window for the dry-run blob-fetch projection.
ASSUMED_WINDOW_COMMITS = 32

_EVENT_COLS = [
    "npm_name", "project_id", "affected_dependency", "affected_version",
    "workspace_scope", "last_seen", "next_snapshot", "lockfile",
    "fix_commit_sha", "fixed_at", "fix_kind", "fix_to_version", "method",
    "status", "n_intervals", "n_commits",
]


def classify_fix(versions_by_lockfile: dict[str, dict[str, set[str]] | None],
                 dependency: str, vulnerable_versions: set[str]
                 ) -> tuple[str, str | None]:
    """Classify how a `found` fix removed the vulnerable versions, from the
    parsed root-lockfile states at the fix commit.

    `versions_by_lockfile` maps lockfile name -> {package: {versions}} (None
    for missing/unparseable lockfiles). If the dependency still resolves in
    any root lockfile at non-vulnerable versions the fix was an upgrade;
    returns ("upgraded", comma-joined surviving versions). If the dependency
    is gone from every parsed root lockfile, returns ("removed", None).
    "removed" only means the package left the resolved dependency tree: it
    conflates a direct dependency deliberately dropped with a transitive
    dependency no longer pulled in because a parent was upgraded. If a
    vulnerable version somehow still resolves (a lockfile outside the search
    set) the row is flagged ("anomalous_still_present", all surviving
    versions) rather than silently misclassified.
    """
    remaining: set[str] = set()
    for versions in versions_by_lockfile.values():
        if versions:
            remaining |= versions.get(dependency, set())
    if remaining & vulnerable_versions:
        return "anomalous_still_present", ",".join(sorted(remaining))
    if remaining:
        return "upgraded", ",".join(sorted(remaining))
    return "removed", None


def classify_removal(deps_at_boundary: set[str] | None,
                     deps_at_fix: set[str] | None,
                     dependency: str) -> str:
    """Split a `classify_fix` "removed" verdict into whether the dependency
    was a deliberately dropped direct dependency or a transitive one that
    left the tree because a parent was upgraded, from the root package.json's
    direct-dependency set (`dependencies` + `devDependencies` +
    `optionalDependencies`) at the boundary (last-seen snapshot) commit and
    at the fix commit.

    Returns "removed_direct" when the dependency was declared at the
    boundary and is no longer declared at the fix commit; "removed_transitive"
    when it was never a direct dependency at the boundary. Either manifest
    being unreadable, or the dependency still being declared at the fix
    commit despite being gone from every lockfile (an inconsistent tree,
    e.g. an unresolved peer), is unknowable and keeps the legacy unsplit
    "removed" value rather than guessing.
    """
    if deps_at_boundary is None or deps_at_fix is None:
        return "removed"
    if dependency in deps_at_boundary and dependency not in deps_at_fix:
        return "removed_direct"
    if dependency not in deps_at_boundary:
        return "removed_transitive"
    return "removed"


class UnparseableLockfile(Exception):
    """A probed lockfile blob could not be parsed — presence is unknowable."""

    def __init__(self, lockfile: str) -> None:
        super().__init__(lockfile)
        self.lockfile = lockfile


@dataclass(frozen=True)
class MiningUnit:
    """One (project, dependency, vulnerable-version-set, window) to mine."""

    npm_name: str
    project_id: str
    git_url: str
    dependency: str
    versions: tuple[str, ...]  # sorted vulnerable resolved versions at last_seen
    last_seen: str  # "YYYY-MM-DD" — the last snapshot where the pair was present
    next_snapshot: str  # "YYYY-MM-DD" — the next completed snapshot (pair absent)
    since: str  # ISO window start (last_seen snapshot's committed_at, or date)
    until: str  # ISO window end (next snapshot's committed_at, or date)
    boundary_sha: str | None  # the last_seen snapshot's analysed commit
    n_intervals: int = field(compare=False, default=1)

    @property
    def unit_key(self) -> str:
        return "|".join((self.npm_name, self.dependency, ",".join(self.versions),
                         self.last_seen, self.next_snapshot))


# --------------------------------------------------------------------------- #
# Unit derivation from the parquet tables
# --------------------------------------------------------------------------- #

def snapshot_entries(analyses: pd.DataFrame) -> dict[str, list[tuple]]:
    """Per-project completed snapshots as (label, resolved_date, commit_hash,
    committed_at), ordered exactly like `stats.presence_intervals` orders them
    (dated snapshots at their date, HEAD at its committed_at — or last dated
    date + 1 day — and last on ties). Kept in lockstep with that function so
    the mined windows line up with the interval identities."""
    snap = analyses[[
        "project_id", "snapshot_date", "commit_hash", "committed_at",
    ]].drop_duplicates(subset=["project_id", "snapshot_date"])
    per: dict[str, list[tuple]] = {}
    for pid, g in snap.groupby("project_id", sort=True):
        entries: list[list] = []  # [label, resolved_date, is_head, sha, committed_at]
        for r in g.itertuples(index=False):
            if r.snapshot_date == "HEAD":
                d = pd.to_datetime(r.committed_at, utc=True, errors="coerce")
                d = d.tz_localize(None).normalize() if pd.notna(d) else pd.NaT
                entries.append([r.snapshot_date, d, True, r.commit_hash, r.committed_at])
            else:
                entries.append([r.snapshot_date, pd.to_datetime(r.snapshot_date),
                                False, r.commit_hash, r.committed_at])
        dated_dates = [e[1] for e in entries if not e[2]]
        for e in entries:
            if e[2] and pd.isna(e[1]) and dated_dates:
                e[1] = max(dated_dates) + pd.Timedelta(days=1)
        entries = [e for e in entries if pd.notna(e[1])]
        entries.sort(key=lambda e: (e[1], e[2]))
        per[pid] = [(e[0], e[1], e[3], e[4]) for e in entries]
    return per


def _iso(value, fallback: str) -> str:
    """A row's committed_at as ISO-8601 Z, else the fallback date-bound."""
    ts = pd.to_datetime(value, utc=True, errors="coerce")
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if pd.notna(ts) else fallback


def derive_units(vulns: pd.DataFrame, analyses: pd.DataFrame
                 ) -> tuple[list[MiningUnit], dict]:
    """Recompute presence intervals and group the event=1 ones into mining
    units. The vulnerable version set is every `affected_version` observed for
    (project, last_seen snapshot, vulnerability, dependency) across ALL
    workspaces — workspace deps resolve from the root lockfile in the common
    monorepo layouts, and the root-only mining verdict is what the `status`
    column reports. Intervals with no recorded version are counted and
    skipped. Returns (units sorted by unit_key, counters)."""
    ints = presence_intervals(vulns, analyses)
    events = ints[ints["event"] == 1]
    entries = snapshot_entries(analyses)
    git_url = (analyses.drop_duplicates("project_id")
               .set_index("project_id")["git_url"].to_dict())

    versions_at: dict[tuple, set[str]] = {}
    vsub = vulns[["project_id", "snapshot_date", "vulnerability_id",
                  "affected_dependency", "affected_version"]].drop_duplicates()
    for r in vsub.itertuples(index=False):
        if pd.notna(r.affected_version) and str(r.affected_version):
            versions_at.setdefault(
                (r.project_id, r.snapshot_date, r.vulnerability_id, r.affected_dependency),
                set(),
            ).add(str(r.affected_version))

    units: dict[tuple, MiningUnit] = {}
    skipped_no_version = 0
    for r in events.itertuples(index=False):
        label = r.last_seen.strftime("%Y-%m-%d")  # event=1 never ends at HEAD
        vers = versions_at.get((r.project_id, label, r.vulnerability_id,
                                r.affected_dependency))
        if not vers:
            skipped_no_version += 1
            continue
        ent = entries[r.project_id]
        i = next(idx for idx, e in enumerate(ent) if e[0] == label)
        nxt = ent[i + 1]
        key = (r.npm_name, r.affected_dependency, frozenset(vers), label)
        if key in units:
            u = units[key]
            units[key] = dataclasses.replace(u, n_intervals=u.n_intervals + 1)
        else:
            units[key] = MiningUnit(
                npm_name=r.npm_name,
                project_id=r.project_id,
                git_url=str(git_url.get(r.project_id, "")),
                dependency=r.affected_dependency,
                versions=tuple(sorted(vers)),
                last_seen=label,
                next_snapshot=nxt[1].strftime("%Y-%m-%d"),
                since=_iso(ent[i][3], f"{label}T00:00:00Z"),
                until=_iso(nxt[3], nxt[1].strftime("%Y-%m-%dT23:59:59Z")),
                boundary_sha=ent[i][2] if isinstance(ent[i][2], str) else None,
            )
    ordered = sorted(units.values(), key=lambda u: u.unit_key)
    counters = {
        "intervals": int(len(ints)),
        "event_intervals": int(len(events)),
        "units": len(ordered),
        "skipped_no_version": skipped_no_version,
    }
    return ordered, counters


def estimate_request_budget(units: list[MiningUnit]) -> dict:
    """Projected request counts for a full mine (dry-run report). Commit-list
    calls dominate the core-API budget; blob fetches are an upper bound before
    cross-unit cache sharing (units in the same window probe the same shas)."""
    windows = {(u.git_url, u.since, u.until) for u in units}
    list_calls = len(windows) * len(ROOT_LOCKFILES)
    probes_per_unit = math.ceil(math.log2(ASSUMED_WINDOW_COMMITS)) + 3
    return {
        "units": len(units),
        "distinct_windows": len(windows),
        "commit_list_calls": list_calls,
        "blob_fetches_upper_bound": len(units) * probes_per_unit,
        "core_api_hours_at_4500_per_h": round(list_calls / 4500, 2),
    }


# --------------------------------------------------------------------------- #
# Cached GitHub access
# --------------------------------------------------------------------------- #

def _cache_file(cache_dir: Path, kind: str, *key: str) -> Path:
    d = cache_dir / kind
    d.mkdir(parents=True, exist_ok=True)
    return d / (hashlib.sha1("|".join(key).encode()).hexdigest() + ".json")


def list_lockfile_commits(http: httpx.Client, cache_dir: Path, slug: str,
                          lockfile: str, since: str, until: str) -> list[dict]:
    """Commits touching `lockfile` in (since, until], oldest first, as
    [{"sha", "date"}] — cached on (slug, lockfile, since, until)."""
    path = _cache_file(cache_dir, "commit_lists", slug, lockfile, since, until)
    if path.exists():
        return json.loads(path.read_text())["commits"]
    commits: list[dict] = []
    page = 1
    while True:
        params = {"path": lockfile, "since": since, "until": until,
                  "per_page": 100, "page": page}
        r = http.get(f"/repos/{slug}/commits", params=params, headers=_gh_headers())
        if r.status_code in (403, 429):
            _handle_rate_limit(r)
            r = http.get(f"/repos/{slug}/commits", params=params, headers=_gh_headers())
        if r.status_code in (404, 409):  # repo gone / empty
            break
        r.raise_for_status()
        batch = r.json()
        commits.extend(
            {"sha": c["sha"], "date": c["commit"]["committer"]["date"]} for c in batch
        )
        if len(batch) < 100:
            break
        page += 1
    commits.sort(key=lambda c: (c["date"], c["sha"]))
    path.write_text(json.dumps({
        "key": {"slug": slug, "lockfile": lockfile, "since": since, "until": until},
        "commits": commits,
    }))
    return commits


def lockfile_versions_at(http_raw: httpx.Client, cache_dir: Path, slug: str,
                         sha: str, lockfile: str
                         ) -> tuple[str, dict[str, set[str]] | None]:
    """Parse `lockfile` at `sha` into {package: {versions}} — cached on
    (slug, sha, lockfile). Returns (status, versions) with status in
    {'parsed', 'missing', 'unparseable'}."""
    path = _cache_file(cache_dir, "blobs", slug, sha, lockfile)
    if path.exists():
        payload = json.loads(path.read_text())
        versions = payload["versions"]
        return payload["status"], (
            {n: set(v) for n, v in versions.items()} if versions is not None else None
        )
    blob = _fetch(http_raw, f"/{slug}/{sha}/{lockfile}")
    status, versions = "missing", None
    if blob is not None:
        try:
            versions = parse_lockfile(lockfile, blob)
            status = "parsed"
        except LockfileParseError as e:
            log.warning("unparseable %s at %s@%.9s: %s", lockfile, slug, sha, e)
            status = "unparseable"
    path.write_text(json.dumps({
        "key": {"slug": slug, "sha": sha, "lockfile": lockfile},
        "status": status,
        "versions": {n: sorted(v) for n, v in versions.items()} if versions is not None else None,
    }))
    return status, versions


def package_json_direct_deps_at(http_raw: httpx.Client, cache_dir: Path, slug: str,
                                sha: str) -> set[str] | None:
    """Direct dependency names (`dependencies` + `devDependencies` +
    `optionalDependencies`) from the root package.json at `sha` — cached on
    (slug, sha, "package.json"). None when the manifest is missing or
    unparseable (unknowable, not "no direct deps"), same convention as
    `lockfile_versions_at`'s missing/unparseable handling."""
    path = _cache_file(cache_dir, "manifests", slug, sha, "package.json")
    if path.exists():
        payload = json.loads(path.read_text())
        deps = payload["deps"]
        return set(deps) if deps is not None else None
    blob = _fetch(http_raw, f"/{slug}/{sha}/package.json")
    deps: set[str] | None = None
    if blob is not None:
        try:
            doc = json.loads(blob.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            doc = None
        if isinstance(doc, dict):
            deps = set()
            for kind in ("dependencies", "devDependencies", "optionalDependencies"):
                block = doc.get(kind)
                if isinstance(block, dict):
                    deps |= {str(name) for name in block}
    path.write_text(json.dumps({
        "key": {"slug": slug, "sha": sha, "name": "package.json"},
        "deps": sorted(deps) if deps is not None else None,
    }))
    return deps


# --------------------------------------------------------------------------- #
# Fix-commit search
# --------------------------------------------------------------------------- #

def _result(status: str, method: str, lockfile: str | None = None,
            commit: dict | None = None) -> dict:
    return {
        "status": status,
        "method": method,
        "lockfile": lockfile,
        "fix_commit_sha": commit["sha"] if commit else None,
        "fixed_at": commit["date"] if commit else None,
    }


def locate_fix(commits: list[dict], present_at, boundary_present) -> dict:
    """Locate the first commit where the vulnerable versions are gone.

    `commits` is the chronological [{"sha", "date"}] candidate list;
    `present_at(sha) -> (bool, lockfile|None)` answers whether any vulnerable
    version occurs in any root lockfile at that commit (and in which);
    `boundary_present() -> (bool, lockfile|None)` answers the same at the
    last-seen snapshot commit. Returns the dict described in the module
    docstring (status/method/lockfile/fix_commit_sha/fixed_at); pure apart
    from the injected probes, so the search is unit-testable offline.
    """
    if not commits:
        return _result("not_found", "no_lockfile_commits")

    n = len(commits)
    if n <= LINEAR_SCAN_MAX:  # exact scan, detects reintroductions
        flags = [present_at(c["sha"]) for c in commits]
        vals = [p for p, _ in flags]
        if any(not vals[i] and vals[i + 1] for i in range(n - 1)):
            return _result("ambiguous", "non_monotonic", flags[-1][1])
        if vals[-1]:
            return _result("ambiguous", "still_present_at_window_end", flags[-1][1])
        k = vals.index(False)
        if k == 0:
            bp, block = boundary_present()
            if not bp:
                return _result("ambiguous", "not_in_root_lockfile")
            return _result("found", "linear_scan", block, commits[0])
        return _result("found", "linear_scan", flags[k - 1][1], commits[k])

    last_p, last_lock = present_at(commits[-1]["sha"])
    if last_p:
        return _result("ambiguous", "still_present_at_window_end", last_lock)
    first_p, first_lock = present_at(commits[0]["sha"])
    if not first_p:
        bp, block = boundary_present()
        if not bp:
            return _result("ambiguous", "not_in_root_lockfile")
        return _result("found", "binary_search", block, commits[0])
    lo, hi = 0, n - 1  # invariant: present at lo, absent at hi
    lo_lock = first_lock
    while hi - lo > 1:
        mid = (lo + hi) // 2
        p, lock = present_at(commits[mid]["sha"])
        if p:
            lo, lo_lock = mid, lock
        else:
            hi = mid
    return _result("found", "binary_search", lo_lock, commits[hi])


def mine_unit(unit: MiningUnit, http_api: httpx.Client, http_raw: httpx.Client,
              cache_dir: Path) -> dict:
    """Mine one unit into a remediation_events row."""
    base = {
        "npm_name": unit.npm_name,
        "project_id": unit.project_id,
        "affected_dependency": unit.dependency,
        "affected_version": ",".join(unit.versions),
        "workspace_scope": "root",
        "last_seen": unit.last_seen,
        "next_snapshot": unit.next_snapshot,
        "n_intervals": unit.n_intervals,
    }
    owner_repo = parse_owner_repo(unit.git_url)
    if not owner_repo:
        return {**base, **_result("not_found", "unparseable_git_url"), "n_commits": 0}
    slug = "/".join(owner_repo)

    by_name = {
        name: list_lockfile_commits(http_api, cache_dir, slug, name,
                                    unit.since, unit.until)
        for name in ROOT_LOCKFILES
    }
    names = [n for n in ROOT_LOCKFILES if by_name[n]]
    seen: set[str] = set()
    commits = sorted(
        (c for n in names for c in by_name[n]
         if not (c["sha"] in seen or seen.add(c["sha"]))),
        key=lambda c: (c["date"], c["sha"]),
    )
    vuln_versions = set(unit.versions)
    probe_cache: dict[str, tuple[bool, str | None]] = {}

    def check(sha: str, lockfiles: list[str]) -> tuple[bool, str | None]:
        # An unparseable lockfile does not, by itself, make presence at this
        # commit unknowable: the other root lockfiles may already answer it
        # definitively (present, or all parsed and absent). Scan every name
        # first; only raise once no parsed lockfile settled the question AND
        # at least one probe was unparseable — presence is genuinely unknown
        # only then. This matters because a single unparseable blob (e.g. one
        # lockfile-migration commit) must not poison every unit that ever
        # probes it.
        unparseable: str | None = None
        for name in lockfiles:
            status, versions = lockfile_versions_at(http_raw, cache_dir, slug, sha, name)
            if status == "unparseable":
                unparseable = unparseable or name
                continue
            if status == "parsed" and versions.get(unit.dependency, set()) & vuln_versions:
                return True, name
        if unparseable is not None:
            raise UnparseableLockfile(unparseable)
        return False, None

    def present_at(sha: str) -> tuple[bool, str | None]:
        if sha not in probe_cache:
            probe_cache[sha] = check(sha, names)
        return probe_cache[sha]

    def boundary_present() -> tuple[bool, str | None]:
        # All three names here: the boundary state may live in a lockfile
        # that saw no commits inside the window.
        if not unit.boundary_sha:
            return False, None
        return check(unit.boundary_sha, ROOT_LOCKFILES)

    try:
        found = locate_fix(commits, present_at, boundary_present)
    except UnparseableLockfile as e:
        found = _result("ambiguous", "unparseable_lockfile", e.lockfile)
    fix_kind, fix_to_version = None, None
    if found["status"] == "found":
        # All three names, not just `names`: the dependency may resolve in a
        # root lockfile that saw no commits inside the window. The `names`
        # blobs are already cached from the search probes; the others are at
        # most two extra raw fetches (usually 404 -> missing).
        states = {
            name: lockfile_versions_at(http_raw, cache_dir, slug,
                                       found["fix_commit_sha"], name)[1]
            for name in ROOT_LOCKFILES
        }
        fix_kind, fix_to_version = classify_fix(states, unit.dependency,
                                                vuln_versions)
        if fix_kind == "removed" and unit.boundary_sha:
            deps_boundary = package_json_direct_deps_at(
                http_raw, cache_dir, slug, unit.boundary_sha)
            deps_fix = package_json_direct_deps_at(
                http_raw, cache_dir, slug, found["fix_commit_sha"])
            fix_kind = classify_removal(deps_boundary, deps_fix, unit.dependency)
    return {**base, **found, "fix_kind": fix_kind,
            "fix_to_version": fix_to_version, "n_commits": len(commits)}


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def run_mining(data_dir: Path, out: Path, limit: int | None = None,
               dry_run: bool = False, http_api: httpx.Client | None = None,
               http_raw: httpx.Client | None = None) -> int:
    """Derive units, mine them (resumably), and write remediation_events.
    `http_api`/`http_raw` are injectable for tests; by default real clients
    against GITHUB_API / RAW_GITHUB are used."""
    tables = data_dir / "tables"
    analyses_path = tables / "analyses.parquet"
    vulns_path = tables / "vulns.parquet"
    if not analyses_path.exists() or not vulns_path.exists():
        log.error("missing %s / %s — run `python run.py collect` first",
                  analyses_path, vulns_path)
        return 1

    analyses = pd.read_parquet(analyses_path)
    vulns = pd.read_parquet(vulns_path)
    units, counters = derive_units(vulns, analyses)
    budget = estimate_request_budget(units)
    log.info("%d mining units from %d event=1 intervals (of %d; %d skipped "
             "for missing version info)", counters["units"],
             counters["event_intervals"], counters["intervals"],
             counters["skipped_no_version"])
    log.info("projected request budget: %s", budget)
    if dry_run:
        print(json.dumps({"counters": counters, "budget": budget}, indent=2))
        return 0

    current_keys = {u.unit_key for u in units}
    if limit:
        units = units[:limit]
    cache_dir = data_dir / "mining_cache"
    results_path = cache_dir / "results.jsonl"
    cache_dir.mkdir(parents=True, exist_ok=True)
    done: dict[str, dict] = {}
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                done[rec["unit_key"]] = rec
    log.info("mining %d unit(s), %d already in %s", len(units),
             sum(1 for u in units if u.unit_key in done), results_path)

    own_api = http_api is None
    own_raw = http_raw is None
    if own_api:
        http_api = httpx.Client(base_url=GITHUB_API, timeout=30.0,
                                follow_redirects=True)
    if own_raw:
        http_raw = httpx.Client(base_url=RAW_GITHUB, timeout=30.0,
                                follow_redirects=True)
    try:
        with results_path.open("a", encoding="utf-8") as sink:
            for unit in tqdm(units, unit="unit", desc="mine-lag"):
                if unit.unit_key in done:
                    continue
                row = mine_unit(unit, http_api, http_raw, cache_dir)
                rec = {"unit_key": unit.unit_key, **row}
                sink.write(json.dumps(rec) + "\n")
                sink.flush()
                done[unit.unit_key] = rec
    finally:
        if own_api:
            http_api.close()
        if own_raw:
            http_raw.close()

    # results.jsonl is an append-only cache across grid changes: a unit whose
    # key no longer derives from the current tables (grid/mining logic
    # changed since it was mined) is a stale cache entry, not a current
    # result, and must not leak into the parquet — a stale wide-window row
    # can share an interval's (project_id, dep, last_seen) key with a fresh
    # narrow-window row, and merge_day_resolution takes the LATEST fixed_at,
    # so a stale entry can silently override a correct one.
    stale = len(done) - sum(1 for k in done if k in current_keys)
    if stale:
        log.info("dropping %d stale cache entr%s not in the current unit set",
                 stale, "y" if stale == 1 else "ies")
    rows = [{k: r.get(k) for k in _EVENT_COLS}
            for key, r in done.items() if key in current_keys]
    df = pd.DataFrame(rows, columns=_EVENT_COLS).sort_values(
        ["npm_name", "affected_dependency", "last_seen"], kind="stable")
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    by_status = df["status"].value_counts().to_dict()
    log.info("wrote %d rows to %s (%s)", len(df), out,
             ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    return 0
