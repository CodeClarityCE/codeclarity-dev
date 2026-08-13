"""Extract every number RESULTS.md cites into data/tables/results_numbers.json.

Single source of truth for the results document: RESULTS.md quotes this file
verbatim, and the numeric audit recomputes from the parquet/manifest primaries.
Run after `collect` (and `triangulate`, if its section is wanted):

    .venv/bin/python scripts/extract_results_numbers.py

Manifest hygiene: rows with snapshot_date == "*" are pre-submission skip
markers (no analysis was ever created); they are excluded from coverage
denominators and panel membership.

Survival is reported in two variants:
  * residence: intervals over ALL observed instances — how long a vulnerable
    version persists in the tree, regardless of when the advisory was
    published (for 43-44% of historical rows publication postdates the
    snapshot, so this is NOT remediation lag).
  * disclosed: intervals restricted to rows whose advisory publication date
    is known and on/before the snapshot date — the defensible
    remediation-lag estimate, at the cost of dropping rows with no
    publication date.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from js_vuln_study.stats import (  # noqa: E402
    disclosed_subset,
    headline,
    km_curve,
    km_median,
    merge_day_resolution,
    presence_intervals,
    sensitivity_sweep,
)

TABLES = ROOT / "data" / "tables"


def _jsonable(x):
    if isinstance(x, (np.integer,)):
        return int(x)
    if isinstance(x, (np.floating,)):
        return float(x)
    return x


def survival_block(vulns: pd.DataFrame, analyses: pd.DataFrame) -> dict:
    ints = presence_intervals(vulns, analyses)
    by_sev = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        s = ints[ints.severity_class.astype(str).str.upper() == sev]
        t, sv = km_curve(s.duration_days, s.event)
        by_sev[sev] = {"n": int(len(s)), "km_median_days": float(km_median(t, sv))}
    classed = sum(v["n"] for v in by_sev.values())
    return {
        "intervals": int(len(ints)),
        "fixed": int(ints.event.sum()),
        "censored": int((1 - ints.event).sum()),
        "unclassed_intervals": int(len(ints) - classed),
        "km_by_severity": by_sev,
    }


def survival_day_block(vulns: pd.DataFrame, analyses: pd.DataFrame,
                       events: pd.DataFrame) -> dict:
    """`survival_block`, but with mined day-resolution fixes folded in via
    `merge_day_resolution` — intervals whose only matching mine is ambiguous
    are excluded from the KM fits but counted."""
    ints = merge_day_resolution(presence_intervals(vulns, analyses), events)
    kept = ints[~ints["excluded"]]
    by_sev = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        s = kept[kept.severity_class.astype(str).str.upper() == sev]
        t, sv = km_curve(s.duration_days, s.event)
        # Short-horizon tail: quarterly snapshots cannot see fixes faster than
        # ~90 days at all, so the share of day-resolution fixes landing within
        # 7/30/90 days is the number day resolution uniquely contributes.
        day_fixed = s[(s.resolution == "day") & (s.event == 1)]
        tail = {
            f"fixed_within_{d}d_pct": float((day_fixed.duration_days <= d).mean() * 100) if len(day_fixed) else None
            for d in (7, 30, 90)
        }
        by_sev[sev] = {
            "n": int(len(s)),
            "n_day_resolution": int((s.resolution == "day").sum()),
            "km_median_days": float(km_median(t, sv)),
            "n_day_fixed": int(len(day_fixed)),
            "n_fix_upgraded": int((day_fixed.fix_kind == "upgraded").sum()),
            "n_fix_removed": int((day_fixed.fix_kind == "removed").sum()),
            **tail,
        }
    out = {
        "intervals": int(len(ints)),
        "fixed": int(ints.event.sum()),
        "day_resolution": int((ints.resolution == "day").sum()),
        "excluded_ambiguous": int(ints.excluded.sum()),
        "km_by_severity": by_sev,
    }
    day_fixed_all = kept[(kept.resolution == "day") & (kept.event == 1)]
    if day_fixed_all.fix_kind.notna().any():
        # Upgrade-only sensitivity: day-resolution fixes classified as
        # dependency removals are DROPPED from the fit (not censored), so
        # removals cannot masquerade as remediation. Quarter-resolution fixes
        # carry no classification and stay in.
        split = {str(k): int(n)
                 for k, n in day_fixed_all.fix_kind.value_counts(dropna=False).items()}
        removed_mask = (kept.resolution == "day") & (kept.event == 1) & (kept.fix_kind == "removed")
        up = kept[~removed_mask]
        up_sev = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            s = up[up.severity_class.astype(str).str.upper() == sev]
            t, sv = km_curve(s.duration_days, s.event)
            day_fixed = s[(s.resolution == "day") & (s.event == 1)]
            up_sev[sev] = {
                "n": int(len(s)),
                "km_median_days": float(km_median(t, sv)),
                "n_day_fixed": int(len(day_fixed)),
                **{
                    f"fixed_within_{d}d_pct": float((day_fixed.duration_days <= d).mean() * 100) if len(day_fixed) else None
                    for d in (7, 30, 90)
                },
            }
        out["fix_kind"] = {
            "day_fixed_split": split,
            "upgrade_only_km_by_severity": up_sev,
        }
    return out


def main() -> None:
    a = pd.read_parquet(TABLES / "analyses.parquet")
    v = pd.read_parquet(TABLES / "vulns.parquet")
    h = a[a.snapshot_date == "HEAD"].copy()
    vh = v[v.snapshot_date == "HEAD"].copy()
    manifest = [
        json.loads(l) for l in (ROOT / "data" / "manifest.jsonl").read_text().splitlines() if l.strip()
    ]
    # "*" rows are pre-submission skip markers, not attempted analyses.
    skip_markers = [r for r in manifest if r["snapshot_date"] == "*"]
    manifest = [r for r in manifest if r["snapshot_date"] != "*"]
    run_meta = json.load(open(TABLES / "run_meta.json"))

    out: dict = {
        "run_meta": {
            k: run_meta.get(k)
            for k in ("knowledge", "analyzer_steps", "api_version", "experiment_sha", "api_sha", "backend_sha", "ts")
        }
    }

    st = Counter(r["status"] for r in manifest)
    hist = [r for r in manifest if r["snapshot_date"] != "HEAD"]
    hist_done = sum(1 for r in hist if r["status"] in ("completed", "success"))
    per_proj: dict[str, list[bool]] = {}
    for r in hist:
        per_proj.setdefault(r["npm_name"], []).append(r["status"] in ("completed", "success"))
    fails = [r for r in manifest if r["status"] in ("failed", "failure")]
    fail_by_repo = Counter(r["npm_name"] for r in fails)
    out["coverage"] = {
        "attempted_analyses": len(manifest),
        "skip_markers": len(skip_markers),
        "statuses": dict(st),
        "head_completed": sum(1 for r in manifest if r["snapshot_date"] == "HEAD" and r["status"] == "completed"),
        "head_total": sum(1 for r in manifest if r["snapshot_date"] == "HEAD"),
        "hist_completed": hist_done,
        "hist_total": len(hist),
        "balanced_panel_18": sum(1 for x in per_proj.values() if len(x) == 18 and all(x)),
        "near_balanced_15": sum(1 for x in per_proj.values() if sum(x) >= 15),
        "per_date_completed": {
            d: sum(1 for r in hist if r["snapshot_date"] == d and r["status"] == "completed")
            for d in sorted({r["snapshot_date"] for r in hist})
        },
        "failures": {
            "total": len(fails),
            "distinct_repos": len(fail_by_repo),
            "top8_share": (sum(n for _, n in fail_by_repo.most_common(8)) / len(fails)) if fails else None,
            "error_classes": dict(Counter((r.get("error") or "")[:45] for r in fails).most_common(3)),
        },
    }

    hl = headline(vh, h)
    out["headline"] = {k: _jsonable(val) for k, val in hl.items()}
    classed = hl["instances"] - hl["sev_counts"]["NONE"]
    out["headline"]["high_critical_share_of_classed"] = (
        (hl["sev_counts"]["CRITICAL"] + hl["sev_counts"]["HIGH"]) / classed if classed else None
    )
    out["sweep"] = json.loads(sensitivity_sweep(vh, h).to_json(orient="records"))

    missing = vh[vh.epss_score.isna()]
    out["epss"] = {
        "nonnull_share": float(vh.epss_score.notna().mean()),
        "median": float(vh.epss_score.median()),
        "p90": float(vh.epss_score.quantile(0.9)),
        "over_10pct": int((vh.epss_score > 0.1).sum()),
        "over_50pct": int((vh.epss_score > 0.5).sum()),
        "missing_non_cve": int((~missing.vulnerability_id.astype(str).str.startswith("CVE-")).sum()),
        "missing_cve": int(missing.vulnerability_id.astype(str).str.startswith("CVE-").sum()),
    }
    out["match_flags"] = {k: int(n) for k, n in vh.conflict_flag.value_counts().items()}
    out["winning_source_head"] = {k: int(n) for k, n in vh.winning_source.value_counts().items()}

    # Survival, both variants (see module docstring).
    hist_v = v[v.snapshot_date != "HEAD"]
    pub = pd.to_datetime(hist_v.published_date, errors="coerce", utc=True)
    snap = pd.to_datetime(hist_v.snapshot_date, errors="coerce", utc=True)
    out["disclosure_coverage_hist"] = {
        "rows": int(len(hist_v)),
        "null_published_share": float(pub.isna().mean()),
        "published_after_snapshot_share": float((pub > snap).mean()),
    }
    out["survival_residence"] = survival_block(v, a)
    disclosed = disclosed_subset(v, a)
    out["survival_disclosed"] = survival_block(disclosed, a)

    # Day-resolution refinement, if `python run.py mine-lag` has produced the
    # remediation events (see js_vuln_study/remediation.py).
    rem_path = TABLES / "remediation_events.parquet"
    if rem_path.exists():
        ev = pd.read_parquet(rem_path)
        out["survival_day_resolution"] = {
            "events": int(len(ev)),
            "by_status": {k: int(n) for k, n in ev.status.value_counts().items()},
            "by_method": {k: int(n) for k, n in ev.method.value_counts().items()},
            "residence": survival_day_block(v, a, ev),
            "disclosed": survival_day_block(disclosed, a, ev),
        }

    from scipy.stats import spearmanr

    sub = h[h.total_dependencies > 0]
    rho, p = spearmanr(sub["rank"], sub.total_vulnerabilities)
    out["rqc"] = {
        "spearman_rho": float(rho),
        "p": float(p),
        "n": int(len(sub)),
        "excluded_zero_dep_projects": int(len(h) - len(sub)),
    }
    pm = (
        h.groupby("package_manager")
        .agg(projects=("project_id", "count"), med_deps=("total_dependencies", "median"), med_vulns=("total_vulnerabilities", "median"))
        .reset_index()
    )
    out["rqd"] = json.loads(pm.to_json(orient="records"))

    tri_path = TABLES / "triangulation.parquet"
    if tri_path.exists():
        t = pd.read_parquet(tri_path)
        pairs = t[t.row_type == "pair"]
        osv = pairs[pairs["pair"] == "codeclarity_vs_osv"]
        proj_rows = t[t.row_type == "project"]
        out["triangulation"] = {
            "n_projects": int(t.npm_name.nunique()),
            "n_with_osv_output": int(osv.npm_name.nunique()),
            "n_with_defined_jaccard": int(osv.jaccard.notna().sum()),
            "osv_jaccard_by_lockfile": {
                k: {"n_defined": int(g.jaccard.notna().sum()), "n_total": int(len(g)), "mean": float(g.jaccard.mean())}
                for k, g in osv.groupby("lockfile")
            },
            # npm audit's own set size: side b in codeclarity_vs_npm_audit,
            # side a in npm_audit_vs_osv (pair names order the sides).
            "npm_audit_all_empty": bool(
                pairs.loc[pairs["pair"] == "codeclarity_vs_npm_audit", "n_b"].fillna(0).eq(0).all()
                and pairs.loc[pairs["pair"] == "npm_audit_vs_osv", "n_a"].fillna(0).eq(0).all()
            ),
            "recall_vs_union_mean": float(proj_rows.recall_vs_union.mean()),
            "recall_defined_projects": int(proj_rows.recall_vs_union.notna().sum()),
            "recall_min": float(proj_rows.recall_vs_union.min()),
            "recall_max": float(proj_rows.recall_vs_union.max()),
        }

    # Balanced-panel point-in-time trajectory (panel from the corrected membership).
    snap_dates = sorted(d for d in a.snapshot_date.unique() if d != "HEAD")
    bal = sorted(p_ for p_, x in per_proj.items() if len(x) == 18 and all(x))
    tt = v[(v.snapshot_date != "HEAD") & (v.npm_name.isin(bal))].copy()
    tt["published"] = pd.to_datetime(tt.published_date, errors="coerce", utc=True)
    tt["snap"] = pd.to_datetime(tt.snapshot_date, utc=True)
    pit = tt[tt.published.notna() & (tt.published <= tt.snap)]
    grid = pd.MultiIndex.from_product([snap_dates, bal], names=["snapshot_date", "npm_name"])
    traj = (
        pit.groupby(["snapshot_date", "npm_name"]).size().reindex(grid, fill_value=0).groupby(level="snapshot_date").mean()
    )
    out["trajectory_balanced"] = {d: float(x) for d, x in traj.items()}
    out["trajectory_balanced_meta"] = {
        "panel_n": len(bal),
        "min": float(traj.min()),
        "max": float(traj.max()),
        "min_2022_2025": float(traj[[d for d in traj.index if d < "2026"]].min()),
        "max_2022_2025": float(traj[[d for d in traj.index if d < "2026"]].max()),
        "pit_rows_used": int(len(pit)),
        "panel_hist_rows_total": int(len(tt)),
    }

    # June->August drift decomposition, if scripts/drift_decomposition.py has
    # run. Loaded verbatim — that script owns the computation; this file stays
    # the single aggregation point RESULTS.md quotes from.
    drift_path = TABLES / "drift_decomposition.json"
    if drift_path.exists():
        out["drift"] = json.load(open(drift_path))

    # Knowledge-staleness ladder dose-response, if
    # scripts/ladder_dose_response.py has run. Loaded verbatim — that script
    # owns the computation; this file stays the single aggregation point
    # RESULTS.md quotes from.
    ladder_path = TABLES / "ladder_dose_response.json"
    if ladder_path.exists():
        out["ladder"] = json.load(open(ladder_path))

    # Passbolt cohort comparison, if scripts/passbolt_compare.py has run
    # against data-passbolt/. Loaded verbatim — that script owns the
    # computation; this file stays the single aggregation point RESULTS.md
    # quotes from.
    passbolt_path = ROOT / "data-passbolt" / "tables" / "passbolt_compare.json"
    if passbolt_path.exists():
        out["passbolt"] = json.load(open(passbolt_path))

    dest = TABLES / "results_numbers.json"
    json.dump(out, open(dest, "w"), indent=1, default=str)
    print(f"wrote {dest}")
    print(
        "panel:", out["coverage"]["balanced_panel_18"],
        "| traj:", round(traj.iloc[0], 2), "->", round(traj.iloc[-1], 2),
        "| survival residence/disclosed intervals:",
        out["survival_residence"]["intervals"], "/", out["survival_disclosed"]["intervals"],
    )


if __name__ == "__main__":
    main()
