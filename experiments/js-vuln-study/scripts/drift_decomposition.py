"""Decompose the June->August drift between the two completed study runs.

Both runs scanned the same sample with the same analyzer versions; what moved
is (a) the knowledge snapshot (NVD/OSV/GCVE/EPSS vintage) and (b) for HEAD
scans, the code itself (HEAD is re-resolved per run, dated snapshots pin a
commit). Pairing runs on (npm_name, snapshot_date) and splitting pairs by
commit equality separates the two: same-commit deltas are pure knowledge
drift; the raw delta additionally contains the code-movement residual.

    .venv/bin/python scripts/drift_decomposition.py \
        [--archive data/archive-run-2026-06-snapshot] [--live data] \
        [--out data/tables/drift_decomposition.json]

Caveats (also embedded under meta.caveats in the output):
  * The HEAD same-commit subset is a subsample (~57 of ~96 paired HEAD scans
    in the real data) — HEAD deltas are reported both restricted (same-commit)
    and unrestricted (all pairs); the restricted one is the knowledge-drift
    estimate, the unrestricted one is what a naive rerun comparison sees.
  * The June run's OSV vintage is an interval, not a point: run_meta stamps
    nvd/gcve mirror timestamps only, so the knowledge date used for advisory
    ages (max stamped source timestamp) is a proxy and the OSV content may
    sit anywhere inside its mirror-update interval.
  * Advisory ages are measured at the LIVE run's knowledge date; rows with
    an unparseable published_date land in the "unknown" bin.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

PAIR_KEY = ["npm_name", "snapshot_date"]
# One "instance" is one reported (project, snapshot, workspace, vuln, package,
# version) occurrence; on same-commit pairs the tree is identical, so instance
# set differences are attributable to the knowledge snapshot alone.
INSTANCE_KEY = PAIR_KEY + ["workspace", "vulnerability_id", "affected_dependency", "affected_version"]
VULN_COLS = INSTANCE_KEY + ["winning_source", "published_date"]

AGE_EDGES = [-np.inf, 30, 90, 365, 3 * 365, np.inf]
AGE_LABELS = ["<30d", "30-90d", "90-365d", "1-3y", ">3y"]

CAVEATS = [
    "HEAD same-commit deltas are a subsample of the paired HEAD scans; the "
    "unrestricted paired_all HEAD delta additionally contains code movement — "
    "both are reported.",
    "The June OSV vintage is an interval, not a point: run_meta stamps nvd/gcve "
    "timestamps only, so knowledge_date (max stamped source) is a proxy.",
    "Advisory ages use the live run's knowledge date; unparseable "
    "published_date rows fall in the 'unknown' bin.",
]


def _load_run(run_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame, dict | None]:
    tables = run_dir / "tables"
    analyses = pd.read_parquet(tables / "analyses.parquet", columns=PAIR_KEY + ["commit_hash"])
    vulns = pd.read_parquet(tables / "vulns.parquet", columns=VULN_COLS)
    meta_path = tables / "run_meta.json"
    meta = json.load(open(meta_path)) if meta_path.exists() else None
    return analyses, vulns, meta


def _knowledge_date(meta: dict | None) -> pd.Timestamp | None:
    """Max parseable knowledge-source timestamp — NOT the run 'ts' (the run
    happens after the mirrors update; the source dates are the vintage)."""
    sources = ((meta or {}).get("knowledge") or {}).get("knowledge_sources") or {}
    stamps = pd.to_datetime(pd.Series(list(sources.values()), dtype="object"), errors="coerce", utc=True)
    stamps = stamps.dropna()
    return stamps.max() if len(stamps) else None


def _delta_pct(archive_n: int, live_n: int) -> float | None:
    return (live_n - archive_n) / archive_n * 100 if archive_n else None


def _keys(df: pd.DataFrame) -> pd.Series:
    return pd.Series(zip(df["npm_name"], df["snapshot_date"]), index=df.index)


def _delta_block(a_v: pd.DataFrame, l_v: pd.DataFrame, keys: set, head_only: bool) -> dict:
    a = a_v[_keys(a_v).isin(keys)]
    l = l_v[_keys(l_v).isin(keys)]
    if head_only:
        a = a[a["snapshot_date"] == "HEAD"]
        l = l[l["snapshot_date"] == "HEAD"]
        keys = {k for k in keys if k[1] == "HEAD"}
    return {
        "n_pairs": len(keys),
        "archive_instances": int(len(a)),
        "live_instances": int(len(l)),
        "delta_pct": _delta_pct(len(a), len(l)),
    }


def _source_block(a_v: pd.DataFrame, l_v: pd.DataFrame, keys: set) -> dict:
    a_by = _keys(a_v).isin(keys).groupby(a_v["winning_source"]).sum()
    l_by = _keys(l_v).isin(keys).groupby(l_v["winning_source"]).sum()
    out = {}
    for src in sorted(set(a_by.index) | set(l_by.index)):
        a_n, l_n = int(a_by.get(src, 0)), int(l_by.get(src, 0))
        out[str(src)] = {
            "archive": a_n,
            "live": l_n,
            "abs_delta": l_n - a_n,
            "rel_delta_pct": _delta_pct(a_n, l_n),
        }
    return out


def _age_bins(published: pd.Series, ref: pd.Timestamp | None) -> dict:
    """Bin advisory age (ref minus published_date) in days; negative ages
    (published after ref — shouldn't happen) land in '<30d'."""
    out = {label: 0 for label in AGE_LABELS}
    pub = pd.to_datetime(published, errors="coerce", utc=True)
    if ref is not None and pub.notna().any():
        age = (ref - pub).dt.days.dropna()
        counts = pd.cut(age, bins=AGE_EDGES, labels=AGE_LABELS, right=False).value_counts()
        out = {label: int(counts.get(label, 0)) for label in AGE_LABELS}
    out["unknown"] = int(pub.isna().sum()) if ref is not None else int(len(pub))
    out["n"] = int(len(pub))
    return out


def decompose(archive_dir: Path | str, live_dir: Path | str) -> dict:
    archive_dir, live_dir = Path(archive_dir), Path(live_dir)
    a_an, a_v, a_meta = _load_run(archive_dir)
    l_an, l_v, l_meta = _load_run(live_dir)

    pairs = a_an.merge(l_an, on=PAIR_KEY, suffixes=("_archive", "_live"))
    pairs["same_commit"] = pairs["commit_hash_archive"] == pairs["commit_hash_live"]
    pairs["is_head"] = pairs["snapshot_date"] == "HEAD"
    paired = set(zip(pairs["npm_name"], pairs["snapshot_date"]))
    same = set(zip(pairs.loc[pairs["same_commit"], "npm_name"], pairs.loc[pairs["same_commit"], "snapshot_date"]))
    a_keys, l_keys = set(_keys(a_an)), set(_keys(l_an))

    def _same_commit_counts(sub: pd.DataFrame) -> dict:
        return {"same_commit": int(sub["same_commit"].sum()), "different_commit": int((~sub["same_commit"]).sum()), "n_pairs": len(sub)}

    l_ref = _knowledge_date(l_meta)

    # Instance-set churn on the same-commit subset (identical trees, so the
    # symmetric difference is knowledge churn: new advisories vs withdrawals).
    a_same = a_v[_keys(a_v).isin(same)].drop_duplicates(INSTANCE_KEY)
    l_same = l_v[_keys(l_v).isin(same)].drop_duplicates(INSTANCE_KEY)
    a_ids = pd.MultiIndex.from_frame(a_same[INSTANCE_KEY])
    l_ids = pd.MultiIndex.from_frame(l_same[INSTANCE_KEY])
    new_i = l_same[~l_ids.isin(a_ids)]
    gone_i = a_same[~a_ids.isin(l_ids)]

    return {
        "meta": {
            "archive_dir": str(archive_dir),
            "live_dir": str(live_dir),
            "knowledge_sources": {
                "archive": ((a_meta or {}).get("knowledge") or {}).get("knowledge_sources"),
                "live": ((l_meta or {}).get("knowledge") or {}).get("knowledge_sources"),
            },
            "knowledge_date": {
                "archive": str(_knowledge_date(a_meta)) if _knowledge_date(a_meta) is not None else None,
                "live": str(l_ref) if l_ref is not None else None,
            },
            "epss_rows": {
                "archive": ((a_meta or {}).get("knowledge") or {}).get("epss_rows"),
                "live": ((l_meta or {}).get("knowledge") or {}).get("epss_rows"),
            },
            "caveats": CAVEATS,
        },
        "totals": {
            "instances": {"archive": int(len(a_v)), "live": int(len(l_v)), "raw_delta_pct": _delta_pct(len(a_v), len(l_v))},
            "instances_head": {
                "archive": int((a_v["snapshot_date"] == "HEAD").sum()),
                "live": int((l_v["snapshot_date"] == "HEAD").sum()),
                "raw_delta_pct": _delta_pct(int((a_v["snapshot_date"] == "HEAD").sum()), int((l_v["snapshot_date"] == "HEAD").sum())),
            },
        },
        "pairing": {
            "n_pairs": len(pairs),
            "archive_only": len(a_keys - l_keys),
            "live_only": len(l_keys - a_keys),
            "same_commit": {
                "overall": _same_commit_counts(pairs),
                "head": _same_commit_counts(pairs[pairs["is_head"]]),
                "dated": _same_commit_counts(pairs[~pairs["is_head"]]),
            },
        },
        "deltas": {
            "paired_all": {
                "overall": _delta_block(a_v, l_v, paired, head_only=False),
                "head": _delta_block(a_v, l_v, paired, head_only=True),
            },
            "same_commit": {
                "overall": _delta_block(a_v, l_v, same, head_only=False),
                "head": _delta_block(a_v, l_v, same, head_only=True),
            },
        },
        "by_winning_source": {
            "paired_all_overall": _source_block(a_v, l_v, paired),
            "same_commit_overall": _source_block(a_v, l_v, same),
        },
        "advisory_age_new_instances": {
            "reference_date": str(l_ref) if l_ref is not None else None,
            "new_same_commit": _age_bins(new_i["published_date"], l_ref),
            "baseline_all_live_same_commit": _age_bins(l_same["published_date"], l_ref),
        },
        "churn_same_commit": {
            "n_pairs": len(same),
            "new_instances": int(len(new_i)),
            "vanished_instances": int(len(gone_i)),
            "new_vuln_package_pairs": int(new_i[["affected_dependency", "vulnerability_id"]].drop_duplicates().shape[0]),
            "vanished_vuln_package_pairs": int(gone_i[["affected_dependency", "vulnerability_id"]].drop_duplicates().shape[0]),
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--archive", type=Path, default=ROOT / "data" / "archive-run-2026-06-snapshot")
    ap.add_argument("--live", type=Path, default=ROOT / "data")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "tables" / "drift_decomposition.json")
    args = ap.parse_args()

    out = decompose(args.archive, args.live)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(out, open(args.out, "w"), indent=1, default=str)
    print(f"wrote {args.out}")
    d, p = out["deltas"], out["pairing"]["same_commit"]
    print(
        "pairs:", out["pairing"]["n_pairs"],
        f"(HEAD same-commit {p['head']['same_commit']}/{p['head']['n_pairs']})",
        "| raw overall/HEAD:",
        f"{d['paired_all']['overall']['delta_pct']:+.2f}% / {d['paired_all']['head']['delta_pct']:+.2f}%",
        "| same-commit overall/HEAD:",
        f"{d['same_commit']['overall']['delta_pct']:+.2f}% / {d['same_commit']['head']['delta_pct']:+.2f}%",
    )
    ch = out["churn_same_commit"]
    print("churn (same-commit): +", ch["new_instances"], "instances / -", ch["vanished_instances"],
          "| pairs: +", ch["new_vuln_package_pairs"], "/ -", ch["vanished_vuln_package_pairs"])


if __name__ == "__main__":
    main()
