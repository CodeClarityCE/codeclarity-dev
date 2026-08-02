"""Shared statistics for the JS vulnerability study.

Pure numpy/pandas (scipy only inside `pairwise_mwu`) — no new dependencies.
Factored out of `notebooks/analysis.py` and `notebooks/report.py` so both
front-ends render the same numbers and the aggregations are unit-testable
(`tests/test_stats.py`).

Cross-sectional helpers (`gini`/`lorenz`/`ecdf`/`pkgs_to_clear`/`headline`/
`sensitivity_sweep`) operate on the HEAD slice of the parquet tables produced
by `python run.py collect`. Survival helpers (`presence_intervals`/`km_curve`)
operate on the full multi-snapshot tables.

Presence-interval semantics (RQ-G)
----------------------------------
A project's *completed snapshots* are the distinct `snapshot_date` values in
its `analyses` rows. Each dated snapshot is placed at its `snapshot_date`; the
"HEAD" row is placed at the date of the commit it analysed (`committed_at`),
which by construction is the branch tip and therefore the latest date — on a
tie with a dated snapshot, HEAD still sorts last. A HEAD row with no
`committed_at` is placed one day after the project's latest dated snapshot.

A (vulnerability_id, affected_dependency) pair present at consecutive
completed snapshots merges into one interval, which ends as:

* event=1 (fixed): the pair is absent at the project's immediately-next
  completed snapshot AND no study-grid date falls in the gap between the two
  (see below). `duration_days` runs from `first_seen` to that next snapshot —
  the fix is *observed* there; the true fix time is interval-censored between
  `last_seen` and that snapshot.
* event=0 (censored): the pair is still present at the project's last
  completed snapshot, OR a coverage gap follows — a date from the study-wide
  dated-snapshot grid falls strictly between this snapshot and the project's
  next completed one, so the disappearance cannot be located between
  consecutive observations. `duration_days` runs from `first_seen` to
  `last_seen`.

Coverage gaps always break runs: presence on both sides of a gap yields two
intervals (we do not assume the pair persisted through the unobserved window).
Projects with fewer than two completed snapshots contribute no intervals — no
transition is observable there.

Worked example — study grid {2024-01-01, 2024-04-01, 2024-07-01}; project P
completed all three snapshots, project Q completed only 01-01 and 07-01:

    P: CVE-X/lodash present at 01-01, absent at 04-01
       -> [01-01, 01-01], event=1, duration 91 d (fix observed at 04-01)
    P: CVE-Y/tar present at all three
       -> [01-01, 07-01], event=0, duration 182 d (still present at end)
    P: CVE-Z/glob present at 01-01 and 07-01 but absent at 04-01
       -> two intervals: [01-01, 01-01] event=1 (91 d), then
          [07-01, 07-01] event=0 (0 d)
    Q: CVE-W/semver present at 01-01, absent at 07-01
       -> [01-01, 01-01], event=0, duration 0 d — the missed 04-01 snapshot
          censors the run (gap), even though the pair later disappears
"""

from __future__ import annotations

import numpy as np
import pandas as pd

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

# Scalar keys of `headline` — the columns of `sensitivity_sweep` rows.
HEADLINE_SCALAR_KEYS = [
    "n_projects", "n_affected", "affected_share", "instances",
    "distinct_vuln_packages", "load_median", "load_mean", "load_max",
    "high_critical_share", "top10_pkg_share", "top10_proj_share",
    "gini_pkg", "gini_proj", "pkgs_clear_50", "pkgs_clear_80", "pkgs_clear_90",
]


# --------------------------------------------------------------------------- #
# Distribution helpers
# --------------------------------------------------------------------------- #

def gini(values) -> float:
    """Gini coefficient of a non-negative array (0 = equal, →1 = concentrated)."""
    x = np.asarray(values, dtype=float)
    x = x[~np.isnan(x)]
    if x.size == 0 or np.all(x == 0):
        return float("nan")
    x = np.sort(x)
    n = x.size
    total = x.sum()
    # Mean absolute difference formulation.
    return float((2.0 * np.sum(np.arange(1, n + 1) * x) - (n + 1) * total) / (n * total))


def lorenz(values):
    """Return (cum_share_x, cum_share_y) points for a Lorenz curve."""
    x = np.asarray(values, dtype=float)
    x = np.sort(x[~np.isnan(x)])
    cum = np.insert(np.cumsum(x), 0, 0)
    pop = np.linspace(0.0, 1.0, cum.size)
    val = cum / cum[-1] if cum[-1] > 0 else np.zeros_like(cum)
    return pop, val


def ecdf(values):
    """Return (sorted_values, cumulative_probability) for an empirical CDF."""
    x = np.sort(np.asarray(values, dtype=float))
    y = np.arange(1, x.size + 1) / x.size
    return x, y


def pairwise_mwu(groups: dict) -> pd.DataFrame:
    """Bonferroni-corrected Mann–Whitney U posthoc across named groups.

    `groups` maps label -> 1d array. Returns a tidy DataFrame of pairwise
    comparisons. Avoids a scikit-posthocs dependency.
    """
    from itertools import combinations

    from scipy.stats import mannwhitneyu

    labels = [k for k, v in groups.items() if len(v) > 1]
    pairs = list(combinations(labels, 2))
    m = max(len(pairs), 1)
    rows = []
    for a, b in pairs:
        try:
            u, p = mannwhitneyu(groups[a], groups[b], alternative="two-sided")
        except ValueError:
            u, p = float("nan"), float("nan")
        rows.append({
            "a": a, "b": b,
            "median_a": float(np.median(groups[a])),
            "median_b": float(np.median(groups[b])),
            "p_raw": p,
            "p_bonferroni": min(p * m, 1.0) if p == p else p,
        })
    return pd.DataFrame(rows)


def pkgs_to_clear(instance_counts, share: float) -> int:
    """Packages needed (ranked by instance count, desc) to remove `share` of
    all vulnerability instances. 0 when there are no instances."""
    x = np.sort(np.asarray(instance_counts, dtype=float))[::-1]
    total = x.sum()
    if x.size == 0 or total <= 0:
        return 0
    cum = np.cumsum(x) / total
    return int((cum < share).sum()) + 1


# --------------------------------------------------------------------------- #
# Headline aggregation + sensitivity sweep
# --------------------------------------------------------------------------- #

def headline(vulns_head: pd.DataFrame, analyses_head: pd.DataFrame) -> dict:
    """Headline summary dict for a HEAD cross-section.

    `analyses_head` fixes the project universe (one row per project at HEAD);
    per-project loads are recomputed from `vulns_head`, zero-filled over that
    universe, so the same function works on *filtered* subsets of the vulns
    frame where the analyses table's precomputed totals no longer apply. Vuln
    rows for projects absent from the universe are dropped.

    Keys: n_projects, n_affected, affected_share, instances,
    distinct_vuln_packages, load_median, load_mean, load_max, sev_counts,
    high_critical_share, top10_pkg_share, top10_proj_share, gini_pkg,
    gini_proj, pkgs_clear_50, pkgs_clear_80, pkgs_clear_90, top_packages
    (list of (package, n_projects_affected), top-10 by spread).
    """
    projects = list(analyses_head["project_id"].drop_duplicates())
    n_projects = len(projects)

    loads = (
        vulns_head.groupby("project_id").size()
        .reindex(projects, fill_value=0)
        .astype(float)
    )
    total = int(loads.sum())
    n_affected = int((loads > 0).sum())

    # Only count instances inside the project universe (matches `loads`).
    in_universe = vulns_head[vulns_head["project_id"].isin(projects)]
    pkg_counts = (
        in_universe.groupby("affected_dependency").size()
        .sort_values(ascending=False, kind="stable")
    )
    instances = int(pkg_counts.sum())

    sev = (
        in_universe["severity_class"].astype(str).str.upper()
        .where(lambda s: s.isin(SEVERITY_ORDER), "NONE")
        .value_counts()
    )
    sev_counts = {k: int(sev.get(k, 0)) for k in SEVERITY_ORDER}
    crit_high = sev_counts["CRITICAL"] + sev_counts["HIGH"]

    # Deterministic tie-break: alphabetical within equal spread.
    spread = (
        in_universe.groupby("affected_dependency")["project_id"].nunique()
        .sort_index()
        .sort_values(ascending=False, kind="stable")
    )

    return {
        "n_projects": n_projects,
        "n_affected": n_affected,
        "affected_share": (n_affected / n_projects) if n_projects else float("nan"),
        "instances": instances,
        "distinct_vuln_packages": int(in_universe["affected_dependency"].nunique()),
        "load_median": float(loads.median()) if n_projects else float("nan"),
        "load_mean": float(loads.mean()) if n_projects else float("nan"),
        "load_max": float(loads.max()) if n_projects else float("nan"),
        "sev_counts": sev_counts,
        "high_critical_share": (crit_high / instances) if instances else float("nan"),
        "top10_pkg_share": (pkg_counts.head(10).sum() / instances) if instances else float("nan"),
        "top10_proj_share": (np.sort(loads.values)[::-1][:10].sum() / total) if total else float("nan"),
        "gini_pkg": gini(pkg_counts.values),
        "gini_proj": gini(loads.values),
        "pkgs_clear_50": pkgs_to_clear(pkg_counts.values, 0.5),
        "pkgs_clear_80": pkgs_to_clear(pkg_counts.values, 0.8),
        "pkgs_clear_90": pkgs_to_clear(pkg_counts.values, 0.9),
        "top_packages": [(name, int(n)) for name, n in spread.head(10).items()],
    }


def sensitivity_sweep(vulns_head: pd.DataFrame, analyses_head: pd.DataFrame) -> pd.DataFrame:
    """Recompute the scalar headline metrics under four vuln-row subsets.

    One row per subset — `all`, `match_correct_only` (conflict_flag ==
    MATCH_CORRECT), `non_withdrawn` (withdrawn_date null/empty), `direct_only`
    (direct_dependency) — with a `subset` label column plus every scalar
    `headline` key (`HEADLINE_SCALAR_KEYS`).
    """
    withdrawn = vulns_head["withdrawn_date"]
    subsets = {
        "all": vulns_head,
        "match_correct_only": vulns_head[
            vulns_head["conflict_flag"].astype(str) == "MATCH_CORRECT"
        ],
        "non_withdrawn": vulns_head[withdrawn.isna() | (withdrawn == "")],
        "direct_only": vulns_head[vulns_head["direct_dependency"].astype(bool)],
    }
    rows = []
    for label, vdf in subsets.items():
        h = headline(vdf, analyses_head)
        rows.append({"subset": label, **{k: h[k] for k in HEADLINE_SCALAR_KEYS}})
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- #
# Survival (RQ-G): presence intervals + Kaplan–Meier
# --------------------------------------------------------------------------- #

_INTERVAL_COLS = [
    "project_id", "npm_name", "vulnerability_id", "affected_dependency",
    "severity_class", "first_seen", "last_seen", "duration_days", "event",
]


def presence_intervals(vulns: pd.DataFrame, analyses: pd.DataFrame) -> pd.DataFrame:
    """One row per presence interval of a (project, vulnerability, package).

    Operates on the full multi-snapshot tables. See the module docstring for
    the exact semantics (snapshot ordering, HEAD placement, event/censoring
    rules, coverage gaps) and a worked example. Returns columns
    project_id, npm_name, vulnerability_id, affected_dependency,
    severity_class (first non-null observed), first_seen, last_seen
    (resolved snapshot dates as Timestamps), duration_days, event (1=fixed,
    0=censored).
    """
    if analyses.empty or vulns.empty:
        return pd.DataFrame(columns=_INTERVAL_COLS)

    snap = analyses[["project_id", "npm_name", "snapshot_date", "committed_at"]] \
        .drop_duplicates(subset=["project_id", "snapshot_date"])
    dated = snap.loc[snap["snapshot_date"] != "HEAD", "snapshot_date"].unique()
    grid = np.sort(pd.to_datetime(dated).values) if len(dated) else np.array([], dtype="datetime64[ns]")

    # Presence sets + first observed severity per (project, vuln, dep).
    presence: dict[tuple[str, str], set[tuple]] = {}
    severity: dict[tuple, str] = {}
    vsub = vulns[[
        "project_id", "snapshot_date", "vulnerability_id",
        "affected_dependency", "severity_class",
    ]].drop_duplicates()
    for r in vsub.itertuples(index=False):
        key = (r.vulnerability_id, r.affected_dependency)
        presence.setdefault((r.project_id, r.snapshot_date), set()).add(key)
        if pd.notna(r.severity_class):
            severity.setdefault((r.project_id, *key), str(r.severity_class))

    rows: list[dict] = []
    for pid, g in snap.groupby("project_id", sort=True):
        entries: list[list] = []  # [label, resolved_date, is_head]
        for r in g.itertuples(index=False):
            if r.snapshot_date == "HEAD":
                d = pd.to_datetime(r.committed_at, utc=True, errors="coerce")
                d = d.tz_localize(None).normalize() if pd.notna(d) else pd.NaT
                entries.append([r.snapshot_date, d, True])
            else:
                entries.append([r.snapshot_date, pd.to_datetime(r.snapshot_date), False])
        dated_dates = [e[1] for e in entries if not e[2]]
        for e in entries:
            if e[2] and pd.isna(e[1]) and dated_dates:
                e[1] = max(dated_dates) + pd.Timedelta(days=1)
        entries = [e for e in entries if pd.notna(e[1])]
        entries.sort(key=lambda e: (e[1], e[2]))  # HEAD last on date ties
        if len(entries) < 2:
            continue

        dates = [e[1] for e in entries]
        gap_after = [
            bool(((grid > np.datetime64(dates[i])) & (grid < np.datetime64(dates[i + 1]))).any())
            for i in range(len(entries) - 1)
        ]
        npm_name = g["npm_name"].iloc[0]
        keys = sorted(
            set().union(*(presence.get((pid, lbl), set()) for lbl, _, _ in entries)),
            key=lambda k: (str(k[0]), str(k[1])),
        )
        for key in keys:
            start = None
            for i, (lbl, d, _) in enumerate(entries):
                if key not in presence.get((pid, lbl), set()):
                    continue  # runs close eagerly, so nothing is dangling here
                if start is None:
                    start = d
                base = {
                    "project_id": pid,
                    "npm_name": npm_name,
                    "vulnerability_id": key[0],
                    "affected_dependency": key[1],
                    "severity_class": severity.get((pid, *key)),
                    "first_seen": start,
                    "last_seen": d,
                }
                if i == len(entries) - 1 or gap_after[i]:
                    # Still present at the last snapshot, or a coverage gap
                    # follows — censor at the last snapshot of the run.
                    rows.append({**base, "duration_days": int((d - start).days), "event": 0})
                    start = None
                elif key not in presence.get((pid, entries[i + 1][0]), set()):
                    rows.append({
                        **base,
                        "duration_days": int((entries[i + 1][1] - start).days),
                        "event": 1,
                    })
                    start = None
                # else: still present at the next consecutive snapshot — merge.

    return pd.DataFrame(rows, columns=_INTERVAL_COLS)


def km_curve(duration_days, event):
    """Kaplan–Meier estimator. Returns (times, survival) numpy arrays.

    `times` starts at 0.0 with survival 1.0 and gains one point per distinct
    event time (censored times only shrink the risk set). Right-censoring
    only — matches the `presence_intervals` output.
    """
    t = np.asarray(duration_days, dtype=float)
    e = np.asarray(event, dtype=int)
    times = [0.0]
    surv = [1.0]
    s = 1.0
    for ut in np.unique(t):
        d = int(np.sum((t == ut) & (e == 1)))
        if d == 0:
            continue
        at_risk = int(np.sum(t >= ut))
        s *= 1.0 - d / at_risk
        times.append(float(ut))
        surv.append(s)
    return np.asarray(times), np.asarray(surv)


def km_median(times, survival) -> float:
    """Smallest time where KM survival drops to <= 0.5 (nan if it never does)."""
    times = np.asarray(times, dtype=float)
    survival = np.asarray(survival, dtype=float)
    hit = np.nonzero(survival <= 0.5)[0]
    return float(times[hit[0]]) if hit.size else float("nan")
