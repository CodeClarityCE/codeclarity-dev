"""Every number RESULTS.md cites, extracted into tables/results_numbers.json.

`python run.py analyze STUDY` runs this after collect (and mine-lag, unless
`--no-mine`); `--baseline OTHER_STUDY` additionally fills the `cohort` block
(a Passbolt-style comparison, generalised from the one-off
`scripts/passbolt_compare.py`). Grid-shaped quantities (the balanced panel,
the near-balanced threshold) are derived from the data
(`analyses.snapshot_date`), not a hard-coded date count, so this module
survives a grid change without silently reporting an empty panel.

Manifest hygiene: rows with snapshot_date == "*" are pre-submission skip
markers (no analysis was ever created); excluded from coverage denominators.

Survival is reported in two variants: `residence` (intervals over ALL
observed instances: how long a vulnerable version persists, regardless of
disclosure date) and `disclosed` (intervals restricted to rows whose
advisory publication date is known and on/before the snapshot: the
defensible remediation-lag estimate).
"""

from __future__ import annotations

import json
import logging
from collections import Counter

import numpy as np
import pandas as pd

from . import manifest
from .config import Study
from .stats import (
    disclosed_subset,
    drop_removed,
    headline,
    km_by_severity,
    km_curve,
    km_median,
    knowledge_stamp,
    merge_day_resolution,
    presence_intervals,
    sensitivity_sweep,
)

log = logging.getLogger(__name__)

MIN_STRATUM = 10
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _jsonable(x):
    if isinstance(x, np.integer):
        return int(x)
    if isinstance(x, np.floating):
        return float(x)
    return x


def load_tables(study: Study):
    a = pd.read_parquet(study.tables_dir / "analyses.parquet")
    v = pd.read_parquet(study.tables_dir / "vulns.parquet")
    ev_path = study.tables_dir / "remediation_events.parquet"
    ev = pd.read_parquet(ev_path) if ev_path.exists() else None
    meta_path = study.tables_dir / "run_meta.json"
    run_meta = json.load(open(meta_path)) if meta_path.exists() else None
    return a, v, ev, run_meta


def _coverage_block(study: Study, grid_len: int) -> dict:
    rows = manifest.read(study.manifest_path)
    attempted = [r for r in rows if r.snapshot_date != "*"]
    skip_markers = [r for r in rows if r.snapshot_date == "*"]
    hist = [r for r in attempted if r.snapshot_date != "HEAD"]
    hist_done = sum(1 for r in hist if r.state == "done")
    per_proj: dict[str, list[bool]] = {}
    for r in hist:
        per_proj.setdefault(r.npm_name, []).append(r.state == "done")
    fails = [r for r in attempted if r.state == "failed"]
    fail_by_repo = Counter(r.npm_name for r in fails)
    near_n = max(1, int(np.ceil(0.83 * grid_len))) if grid_len else 0
    balanced = sum(1 for x in per_proj.values() if len(x) == grid_len and all(x))
    return {
        "attempted_analyses": len(attempted),
        "skip_markers": len(skip_markers),
        "statuses": dict(Counter(r.server_status or r.state for r in attempted)),
        "head_completed": sum(1 for r in attempted if r.snapshot_date == "HEAD" and r.state == "done"),
        "head_total": sum(1 for r in attempted if r.snapshot_date == "HEAD"),
        "hist_completed": hist_done,
        "hist_total": len(hist),
        "grid_len": grid_len,
        "balanced_panel": balanced,
        "balanced_panel_18": balanced,  # alias for one release
        "near_balanced": sum(1 for x in per_proj.values() if sum(x) >= near_n),
        "per_date_completed": {
            d: sum(1 for r in hist if r.snapshot_date == d and r.state == "done")
            for d in sorted({r.snapshot_date for r in hist})
        },
        "failures": {
            "total": len(fails),
            "distinct_repos": len(fail_by_repo),
            "top8_share": (sum(n for _, n in fail_by_repo.most_common(8)) / len(fails)) if fails else None,
            "error_classes": dict(Counter((r.error or "")[:45] for r in fails).most_common(3)),
        },
    }


def _survival_block(vulns: pd.DataFrame, analyses: pd.DataFrame) -> dict:
    ints = presence_intervals(vulns, analyses)
    by_sev = km_by_severity(ints)
    classed = sum(v["n"] for v in by_sev.values())
    return {
        "intervals": int(len(ints)), "fixed": int(ints.event.sum()),
        "censored": int((1 - ints.event).sum()),
        "unclassed_intervals": int(len(ints) - classed),
        "km_by_severity": by_sev,
    }


def _survival_day_block(vulns: pd.DataFrame, analyses: pd.DataFrame, events: pd.DataFrame) -> dict:
    ints = merge_day_resolution(presence_intervals(vulns, analyses), events)
    kept = ints[~ints["excluded"]]
    out = {
        "intervals": int(len(ints)), "fixed": int(ints.event.sum()),
        "day_resolution": int((ints.resolution == "day").sum()),
        "excluded_ambiguous": int(ints.excluded.sum()),
        "km_by_severity": km_by_severity(kept),
    }
    day_fixed_all = kept[(kept.resolution == "day") & (kept.event == 1)]
    if day_fixed_all.fix_kind.notna().any():
        split = {str(k): int(n) for k, n in day_fixed_all.fix_kind.value_counts(dropna=False).items()}
        out["fix_kind"] = {
            "day_fixed_split": split,
            "upgrade_only_km_by_severity": km_by_severity(drop_removed(kept)),
        }
    return out


def build_numbers(study: Study, baseline: Study | None = None) -> dict:
    a, v, ev, run_meta = load_tables(study)
    h = a[a.snapshot_date == "HEAD"].copy()
    vh = v[v.snapshot_date == "HEAD"].copy()
    grid = sorted(d for d in a.snapshot_date.unique() if d != "HEAD")

    out: dict = {
        "run_meta": {
            k: (run_meta or {}).get(k)
            for k in ("knowledge", "analyzer_steps", "api_version", "experiment_sha", "api_sha", "backend_sha", "ts")
        },
    }
    out["coverage"] = _coverage_block(study, len(grid))

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

    hist_v = v[v.snapshot_date != "HEAD"]
    pub = pd.to_datetime(hist_v.published_date, errors="coerce", utc=True)
    snap = pd.to_datetime(hist_v.snapshot_date, errors="coerce", utc=True)
    out["disclosure_coverage_hist"] = {
        "rows": int(len(hist_v)),
        "null_published_share": float(pub.isna().mean()),
        "published_after_snapshot_share": float((pub > snap).mean()),
    }
    out["survival_residence"] = _survival_block(v, a)
    disclosed = disclosed_subset(v, a)
    out["survival_disclosed"] = _survival_block(disclosed, a)

    if ev is not None:
        out["survival_day_resolution"] = {
            "events": int(len(ev)),
            "by_status": {k: int(n) for k, n in ev.status.value_counts().items()},
            "by_method": {k: int(n) for k, n in ev.method.value_counts().items()},
            "residence": _survival_day_block(v, a, ev),
            "disclosed": _survival_day_block(disclosed, a, ev),
        }

    from scipy.stats import spearmanr

    sub = h[h.total_dependencies > 0]
    rho, p = spearmanr(sub["rank"], sub.total_vulnerabilities)
    out["rqc"] = {
        "spearman_rho": float(rho), "p": float(p), "n": int(len(sub)),
        "excluded_zero_dep_projects": int(len(h) - len(sub)),
    }
    pm = (
        h.groupby("package_manager")
        .agg(projects=("project_id", "count"), med_deps=("total_dependencies", "median"),
             med_vulns=("total_vulnerabilities", "median"))
        .reset_index()
    )
    out["rqd"] = json.loads(pm.to_json(orient="records"))

    tri_path = study.tables_dir / "triangulation.parquet"
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
            "recall_vs_union_mean": float(proj_rows.recall_vs_union.mean()),
            "recall_defined_projects": int(proj_rows.recall_vs_union.notna().sum()),
            "recall_min": float(proj_rows.recall_vs_union.min()),
            "recall_max": float(proj_rows.recall_vs_union.max()),
        }

    all_rows = manifest.read(study.manifest_path)
    per_proj_hist: dict[str, list[bool]] = {}
    for r in all_rows:
        if r.snapshot_date in ("HEAD", "*"):
            continue
        per_proj_hist.setdefault(r.npm_name, []).append(r.state == "done")
    bal = sorted(npm for npm, x in per_proj_hist.items() if len(x) == len(grid) and all(x))
    tt = v[(v.snapshot_date != "HEAD") & (v.npm_name.isin(bal))].copy()
    if len(bal) and len(grid):
        tt["published"] = pd.to_datetime(tt.published_date, errors="coerce", utc=True)
        tt["snap"] = pd.to_datetime(tt.snapshot_date, utc=True)
        pit = tt[tt.published.notna() & (tt.published <= tt.snap)]
        idx = pd.MultiIndex.from_product([grid, bal], names=["snapshot_date", "npm_name"])
        traj = (
            pit.groupby(["snapshot_date", "npm_name"]).size().reindex(idx, fill_value=0)
            .groupby(level="snapshot_date").mean()
        )
        out["trajectory_balanced"] = {d: float(x) for d, x in traj.items()}
        out["trajectory_balanced_meta"] = {
            "panel_n": len(bal), "min": float(traj.min()), "max": float(traj.max()),
            "pit_rows_used": int(len(pit)), "panel_hist_rows_total": int(len(tt)),
        }
    else:
        out["trajectory_balanced"] = {}
        out["trajectory_balanced_meta"] = {"panel_n": 0}

    # Frozen appendix (sections 13-15): committed once, if the operator's
    # machine still holds them, under archive/<date>/. Loaded verbatim.
    archive_dir = study.dir.parent.parent / "archive"
    if archive_dir.is_dir():
        for name, key in (
            ("ladder_dose_response.json", "ladder"),
            ("drift_decomposition.json", "drift"),
        ):
            candidates = sorted(archive_dir.glob(f"*/{name}"))
            if candidates:
                out[key] = json.load(open(candidates[-1]))

    if baseline is not None:
        out["cohort"] = compare_cohorts(baseline, study, recency_cutoff=study.recency_cutoff)

    dest = study.tables_dir / "results_numbers.json"
    dest.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    log.info("wrote %s", dest)
    return out


# --------------------------------------------------------------------------- #
# Cohort comparison (generalised scripts/passbolt_compare.py)
# --------------------------------------------------------------------------- #


def _km_block(df: pd.DataFrame) -> dict:
    """KM summary of one pooled interval stratum (not split by severity;
    `km_by_severity` is for that). n reported always, a fit only once the
    stratum reaches MIN_STRATUM."""
    block: dict = {
        "n": int(len(df)), "n_fixed": int(df.event.sum()),
        "censored_share": float((1 - df.event).mean()) if len(df) else None,
        "n_day_resolution": int((df.resolution == "day").sum()) if "resolution" in df.columns else 0,
    }
    if len(df) < MIN_STRATUM:
        block["km_median_days"] = None
        return block
    t, sv = km_curve(df.duration_days, df.event)
    block["km_median_days"] = float(km_median(t, sv))
    if "resolution" in df.columns:
        day_fixed = df[(df.resolution == "day") & (df.event == 1)]
        block["n_day_fixed"] = int(len(day_fixed))
        for d in (7, 30, 90):
            block[f"fixed_within_{d}d_pct"] = (
                float((day_fixed.duration_days <= d).mean() * 100) if len(day_fixed) else None
            )
    return block


def _fix_kind_split(kept: pd.DataFrame) -> dict:
    day_fixed = kept[(kept.resolution == "day") & (kept.event == 1)]
    return {str(k): int(n) for k, n in day_fixed.fix_kind.value_counts(dropna=False).items()}


def _cohort_block(study: Study, recency_cutoff: pd.Timestamp) -> tuple[dict, dict | None]:
    a, v, ev, run_meta = load_tables(study)
    disclosed = disclosed_subset(v, a)
    ints = merge_day_resolution(presence_intervals(disclosed, a), ev)
    kept = ints[~ints["excluded"]].copy()

    pub = pd.to_datetime(disclosed.published_date, errors="coerce", utc=True)
    first_pub = pub.dt.tz_localize(None).groupby(disclosed.vulnerability_id).min()
    kept["published"] = kept.vulnerability_id.map(first_pub)
    recent = kept[kept.published >= recency_cutoff]
    older = kept[kept.published < recency_cutoff]

    block = {
        "study": study.name,
        "n_projects": int(a.project_id.nunique()),
        "head_committed_at": sorted(
            a[a.snapshot_date == "HEAD"].committed_at.dropna().astype(str).unique().tolist()
        ),
        "intervals": int(len(ints)),
        "excluded_ambiguous": int(ints.excluded.sum()),
        "fix_kind_split": _fix_kind_split(kept),
        "pooled": _km_block(kept),
        "by_severity": {
            sev: _km_block(kept[kept.severity_class.astype(str).str.upper() == sev]) for sev in SEVERITIES
        },
        "recency": {
            "cutoff": recency_cutoff.strftime("%Y-%m-%d"),
            "disclosed_on_or_after": _km_block(recent),
            "disclosed_before": _km_block(older),
        },
        "upgrade_only": {
            "pooled": _km_block(drop_removed(kept)),
            "n_removed_dropped": int(len(kept) - len(drop_removed(kept))),
            "recency": {
                "disclosed_on_or_after": _km_block(drop_removed(recent)),
                "disclosed_before": _km_block(drop_removed(older)),
            },
        },
        "by_repo": (
            {name: _km_block(kept[kept.npm_name == name]) for name in sorted(kept.npm_name.unique())}
            if len(kept.npm_name.unique()) <= 10 else None
        ),
    }
    return block, run_meta


def compare_cohorts(baseline: Study, cohort: Study, recency_cutoff: str = "2024-01-01") -> dict:
    """Compare `cohort`'s post-disclosure fix speed against `baseline`
    (generalised from the Passbolt-vs-top100 comparison)."""
    cutoff = pd.Timestamp(recency_cutoff)
    base_block, base_meta = _cohort_block(baseline, cutoff)
    cohort_block, cohort_meta = _cohort_block(cohort, cutoff)
    match = knowledge_stamp(base_meta) == knowledge_stamp(cohort_meta)
    if not match:
        log.warning(
            "knowledge stamps differ between %s and %s - cross-cohort deltas "
            "include knowledge drift", baseline.name, cohort.name,
        )
    return {
        "meta": {
            "recency_cutoff": cutoff.strftime("%Y-%m-%d"),
            "min_stratum": MIN_STRATUM,
            "knowledge_stamps_match": bool(match),
        },
        "baseline": base_block,
        "cohort": cohort_block,
    }
