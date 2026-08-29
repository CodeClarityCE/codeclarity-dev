"""Compare a cohort's post-disclosure fix speed against the top-100 baseline.

Built for the Passbolt cohort (data-passbolt/) but cohort-agnostic: both data
dirs flow through the exact same shared helpers (`presence_intervals`,
`merge_day_resolution`, `km_curve`, `disclosed_subset` from
`js_vuln_study.stats`), so the comparison cannot diverge from the paper's own
numbers. The subject is the DISCLOSED survival variant: intervals start at
the first snapshot where a vulnerability was observed with its advisory
already published, and end when the pair leaves the tree (day-resolution
where the miner found the fix commit, quarter-resolution otherwise;
ambiguous-mined intervals are excluded from fits but counted).

    .venv/bin/python scripts/passbolt_compare.py \
        [--baseline data] [--cohort data-passbolt] \
        [--recency-cutoff 2024-01-01] [--out <cohort>/tables/passbolt_compare.json]

Outputs the JSON (loaded verbatim into results_numbers.json under
"passbolt") plus KM figures under <cohort>/report/.

Guardrails encoded here rather than left to prose:
  * knowledge stamps of both runs are compared and any mismatch is recorded
    in meta.knowledge_stamps and warned about loudly — cross-cohort deltas
    are only meaningful against the same knowledge DB;
  * severity strata and splits with fewer than MIN_STRATUM intervals report
    n but no KM fit;
  * day-resolution fixes classified as dependency removals are dropped (not
    counted as remediation) in the upgrade_only sensitivity, in BOTH cohorts.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from js_vuln_study.stats import (  # noqa: E402
    disclosed_subset,
    km_curve,
    km_median,
    merge_day_resolution,
    presence_intervals,
)

log = logging.getLogger("passbolt_compare")

MIN_STRATUM = 10
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

CAVEATS = [
    "The cohort is 3 repositories against 97 baseline projects; per-severity "
    "and per-repo cells are small and reported with their n.",
    "Quarterly presence detection cannot see a vulnerability introduced and "
    "fixed within a single quarter, which biases AGAINST fast fixers in both "
    "cohorts (fast fixes are undercounted, not overcounted).",
    "Interval clocks start at the first snapshot where the pair was observed "
    "with the advisory already published, not at the publication instant, "
    "identically in both cohorts.",
    "upgrade_only drops day-resolution fixes classified as dependency "
    "removals (removed_direct, removed_transitive, or the unsplit legacy "
    "removed); quarter-resolution fixes carry no classification and stay in.",
]


def _load(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame | None, dict | None]:
    tables = data_dir / "tables"
    analyses = pd.read_parquet(tables / "analyses.parquet")
    vulns = pd.read_parquet(tables / "vulns.parquet")
    ev_path = tables / "remediation_events.parquet"
    events = pd.read_parquet(ev_path) if ev_path.exists() else None
    meta_path = tables / "run_meta.json"
    run_meta = json.load(open(meta_path)) if meta_path.exists() else None
    return analyses, vulns, events, run_meta


def _km_block(df: pd.DataFrame) -> dict:
    """KM summary of one interval stratum; n reported always, fit only when
    the stratum is large enough to mean anything."""
    out: dict = {
        "n": int(len(df)),
        "n_fixed": int(df.event.sum()),
        "censored_share": float((1 - df.event).mean()) if len(df) else None,
        "n_day_resolution": int((df.resolution == "day").sum()),
    }
    if len(df) < MIN_STRATUM:
        out["km_median_days"] = None
        return out
    t, sv = km_curve(df.duration_days, df.event)
    out["km_median_days"] = float(km_median(t, sv))
    day_fixed = df[(df.resolution == "day") & (df.event == 1)]
    out["n_day_fixed"] = int(len(day_fixed))
    for d in (7, 30, 90):
        out[f"fixed_within_{d}d_pct"] = (
            float((day_fixed.duration_days <= d).mean() * 100) if len(day_fixed) else None
        )
    return out


REMOVED_KINDS = ("removed", "removed_direct", "removed_transitive")


def _drop_removed(kept: pd.DataFrame) -> pd.DataFrame:
    mask = ((kept.resolution == "day") & (kept.event == 1)
            & kept.fix_kind.isin(REMOVED_KINDS))
    return kept[~mask]


def _fix_kind_split(kept: pd.DataFrame) -> dict:
    day_fixed = kept[(kept.resolution == "day") & (kept.event == 1)]
    counts = day_fixed.fix_kind.value_counts(dropna=False)
    return {str(k): int(n) for k, n in counts.items()}


def _cohort_block(data_dir: Path, recency_cutoff: pd.Timestamp) -> tuple[dict, dict | None]:
    analyses, vulns, events, run_meta = _load(data_dir)
    disclosed = disclosed_subset(vulns, analyses)
    ints = merge_day_resolution(presence_intervals(disclosed, analyses), events)
    kept = ints[~ints["excluded"]].copy()

    # Disclosure date per interval: earliest parseable published_date of the
    # vulnerability anywhere in the cohort's disclosed frame.
    pub = pd.to_datetime(disclosed.published_date, errors="coerce", utc=True)
    first_pub = (pub.dt.tz_localize(None)
                 .groupby(disclosed.vulnerability_id).min())
    kept["published"] = kept.vulnerability_id.map(first_pub)

    recent = kept[kept.published >= recency_cutoff]
    older = kept[kept.published < recency_cutoff]

    block = {
        "data_dir": str(data_dir.name),
        "n_projects": int(analyses.project_id.nunique()),
        "head_committed_at": sorted(
            analyses[analyses.snapshot_date == "HEAD"].committed_at
            .dropna().astype(str).unique().tolist()),
        "intervals": int(len(ints)),
        "excluded_ambiguous": int(ints.excluded.sum()),
        "fix_kind_split": _fix_kind_split(kept),
        "pooled": _km_block(kept),
        "by_severity": {
            sev: _km_block(kept[kept.severity_class.astype(str).str.upper() == sev])
            for sev in SEVERITIES
        },
        "recency": {
            "cutoff": recency_cutoff.strftime("%Y-%m-%d"),
            "disclosed_on_or_after": _km_block(recent),
            "disclosed_before": _km_block(older),
        },
        "upgrade_only": {
            "pooled": _km_block(_drop_removed(kept)),
            "n_removed_dropped": int(len(kept) - len(_drop_removed(kept))),
            "recency": {
                "disclosed_on_or_after": _km_block(_drop_removed(recent)),
                "disclosed_before": _km_block(_drop_removed(older)),
            },
        },
        "by_repo": {
            name: _km_block(kept[kept.npm_name == name])
            for name in sorted(kept.npm_name.unique())
        } if len(kept.npm_name.unique()) <= 10 else None,
    }
    return block, run_meta


def _stamp_check(base_meta: dict | None, cohort_meta: dict | None) -> dict:
    base = (base_meta or {}).get("knowledge")
    cohort = (cohort_meta or {}).get("knowledge")

    def _norm(k):
        # Drop null-valued sources: the provenance endpoint gained keys (e.g.
        # "osv": null) between runs; a source that stamps nothing on both
        # sides carries no vintage information and must not fail the guard.
        if not isinstance(k, dict):
            return None
        srcs = {n: v for n, v in (k.get("knowledge_sources") or {}).items()
                if v not in (None, "0")}
        return (tuple(sorted(srcs.items())), k.get("epss_rows"))

    match = base is not None and _norm(base) == _norm(cohort)
    if not match:
        log.warning("knowledge stamps differ between baseline and cohort — "
                    "cross-cohort deltas include knowledge drift!\n"
                    "baseline: %s\ncohort:   %s", base, cohort)
    return {"match": bool(match), "baseline": base, "cohort": cohort}


def _figures(base_dir: Path, cohort_dir: Path, recency_cutoff: pd.Timestamp,
             out_dir: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def kept_of(d: Path) -> pd.DataFrame:
        analyses, vulns, events, _ = _load(d)
        disclosed = disclosed_subset(vulns, analyses)
        ints = merge_day_resolution(presence_intervals(disclosed, analyses), events)
        kept = ints[~ints["excluded"]].copy()
        pub = pd.to_datetime(disclosed.published_date, errors="coerce", utc=True)
        first_pub = pub.dt.tz_localize(None).groupby(disclosed.vulnerability_id).min()
        kept["published"] = kept.vulnerability_id.map(first_pub)
        return kept

    base_kept, cohort_kept = kept_of(base_dir), kept_of(cohort_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    def step(ax, df, label, color, style="-"):
        if len(df) < MIN_STRATUM:
            return
        t, sv = km_curve(df.duration_days, df.event)
        ax.step(t, sv, where="post", label=f"{label} (n={len(df)})",
                color=color, linestyle=style, linewidth=2)

    fig, ax = plt.subplots(figsize=(7, 4.2))
    step(ax, base_kept, "top-100 baseline", "#08519c")
    step(ax, cohort_kept, "Passbolt", "#de2d26")
    ax.axhline(0.5, color="#999999", linestyle=":", linewidth=1)
    ax.set_xlabel("days since first post-disclosure observation")
    ax.set_ylabel("share not yet fixed")
    ax.set_xlim(0, 1000)
    ax.set_ylim(0, 1)
    ax.legend(frameon=False)
    ax.set_title("Time to fix disclosed vulnerabilities")
    fig.tight_layout()
    p = out_dir / "km_pooled.png"
    fig.savefig(p, dpi=200)
    plt.close(fig)
    written.append(str(p))

    fig, ax = plt.subplots(figsize=(7, 4.2))
    cut = recency_cutoff.strftime("%Y")
    step(ax, base_kept[base_kept.published < recency_cutoff],
         f"baseline, pre-{cut}", "#9ecae1")
    step(ax, base_kept[base_kept.published >= recency_cutoff],
         f"baseline, {cut}+", "#08519c")
    step(ax, cohort_kept[cohort_kept.published < recency_cutoff],
         f"Passbolt, pre-{cut}", "#fcae91")
    step(ax, cohort_kept[cohort_kept.published >= recency_cutoff],
         f"Passbolt, {cut}+", "#de2d26")
    ax.axhline(0.5, color="#999999", linestyle=":", linewidth=1)
    ax.set_xlabel("days since first post-disclosure observation")
    ax.set_ylabel("share not yet fixed")
    ax.set_xlim(0, 1000)
    ax.set_ylim(0, 1)
    ax.legend(frameon=False, fontsize=8)
    ax.set_title(f"Fix speed by disclosure era (cutoff {recency_cutoff.date()})")
    fig.tight_layout()
    p = out_dir / "km_recency.png"
    fig.savefig(p, dpi=200)
    plt.close(fig)
    written.append(str(p))
    return written


def compute(baseline_dir: Path, cohort_dir: Path,
            recency_cutoff: str = "2024-01-01") -> dict:
    cutoff = pd.Timestamp(recency_cutoff)
    base_block, base_meta = _cohort_block(baseline_dir, cutoff)
    cohort_block, cohort_meta = _cohort_block(cohort_dir, cutoff)
    return {
        "meta": {
            "recency_cutoff": cutoff.strftime("%Y-%m-%d"),
            "min_stratum": MIN_STRATUM,
            "knowledge_stamps": _stamp_check(base_meta, cohort_meta),
            "caveats": CAVEATS,
        },
        "baseline": base_block,
        "cohort": cohort_block,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--baseline", default="data", type=Path)
    ap.add_argument("--cohort", default="data-passbolt", type=Path)
    ap.add_argument("--recency-cutoff", default="2024-01-01")
    ap.add_argument("--out", default=None, type=Path)
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    baseline = args.baseline if args.baseline.is_absolute() else ROOT / args.baseline
    cohort = args.cohort if args.cohort.is_absolute() else ROOT / args.cohort
    out_path = args.out or (cohort / "tables" / "passbolt_compare.json")

    result = compute(baseline, cohort, args.recency_cutoff)
    if not args.no_figures:
        result["figures"] = _figures(baseline, cohort,
                                     pd.Timestamp(args.recency_cutoff),
                                     cohort / "report")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    log.info("wrote %s", out_path)
    print(json.dumps({
        "pooled_median_days": {
            "baseline": result["baseline"]["pooled"]["km_median_days"],
            "cohort": result["cohort"]["pooled"]["km_median_days"],
        },
        "recent_median_days": {
            "baseline": result["baseline"]["recency"]["disclosed_on_or_after"]["km_median_days"],
            "cohort": result["cohort"]["recency"]["disclosed_on_or_after"]["km_median_days"],
        },
        "stamps_match": result["meta"]["knowledge_stamps"]["match"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
