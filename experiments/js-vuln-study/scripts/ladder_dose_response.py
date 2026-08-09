"""Dose-response of measured vulnerability exposure vs knowledge-DB staleness.

The ladder re-scans the archived 2026-06 run's exact pinned commits under
several DATED knowledge-DB states (rungs), with the backend code held fixed, so
every result delta is attributable to the vulnerability-database state alone.
This script aggregates the per-rung `collect` outputs into one JSON:

    .venv/bin/python scripts/ladder_dose_response.py \
        --rungs 'data-ladder/rung-*' \
        [--archive data/archive-run-2026-06-snapshot] \
        [--out data/tables/ladder_dose_response.json]

Per rung (sorted stalest -> freshest by the run_meta knowledge date — an
explicit `knowledge_asof` extra when present, since runtime-filtered rungs all
share one live DB whose stamps don't identify them; else the OSV mirror stamp,
since the dump-restore ladder rebuilds OSV per rung; else the max parseable
source stamp as in drift_decomposition): completed analyses, total
instances, instances on the COMMON completed-analysis subset (the
(git_url, commit_hash) keys completed in EVERY rung — the like-for-like panel),
severity-class and winning-source mixes on that subset, and pairwise deltas vs
the freshest rung (common-subset instance delta + Jaccard of the
(affected_dependency, vulnerability_id) pair sets). api_sha/backend_sha must
match across rungs — a mismatch breaks the "code held fixed" premise, so it is
WARNED about (never crashed on) and flagged in the output. If some rung's
knowledge date lands within FIDELITY_TOLERANCE_DAYS of the archive's, that rung
is additionally compared against the archived tables on the same-key join —
this bounds the fidelity of the dated-state reconstruction.
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]

# Rungs scan the same frozen trees, so (git_url, commit_hash) — not
# (npm_name, snapshot_date) — is the cross-rung analysis identity: with
# --dedupe-sha one tree carries one arbitrary representative snapshot_date.
JOIN_KEY = ["git_url", "commit_hash"]
# One "instance" is one reported (tree, workspace, vuln, package, version)
# occurrence; trees are identical across rungs, so instance-set differences are
# attributable to the knowledge state alone.
INSTANCE_KEY = JOIN_KEY + ["workspace", "vulnerability_id", "affected_dependency", "affected_version"]
VULN_COLS = INSTANCE_KEY + ["severity_class", "winning_source"]

# A rung whose knowledge date is within this many days of the archive's is
# treated as the archive's reconstruction and compared against it directly.
FIDELITY_TOLERANCE_DAYS = 3


def _load_run(run_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame, dict | None]:
    tables = run_dir / "tables"
    analyses = pd.read_parquet(tables / "analyses.parquet", columns=JOIN_KEY)
    vulns = pd.read_parquet(tables / "vulns.parquet", columns=VULN_COLS)
    meta_path = tables / "run_meta.json"
    meta = json.load(open(meta_path)) if meta_path.exists() else None
    return analyses, vulns, meta


def _knowledge_date(meta: dict | None) -> pd.Timestamp | None:
    """The rung's knowledge vintage. Prefer an explicit `knowledge_asof` (a
    run_meta extra recorded by `resubmit-frozen --knowledge-asof`, stored
    top-level since capture_run_meta merges extras into the record): under
    runtime filtering the DB is NOT restored per rung, so its stamps describe
    the shared live state, not this rung's dose — only the requested cutoff
    does. Next prefer the OSV stamp — the dump-restore ladder rebuilds OSV per
    rung while nvd/gcve/npm stay frozen at the natural dump, so the max stamp
    would misreport every dated rung. Fall back to the max parseable source
    stamp (drift_decomposition's proxy) when OSV is unstamped."""
    asof = pd.to_datetime((meta or {}).get("knowledge_asof"), errors="coerce", utc=True)
    if pd.notna(asof):
        return asof
    sources = ((meta or {}).get("knowledge") or {}).get("knowledge_sources") or {}
    osv = pd.to_datetime(sources.get("osv"), errors="coerce", utc=True)
    if pd.notna(osv):
        return osv
    stamps = pd.to_datetime(pd.Series(list(sources.values()), dtype="object"), errors="coerce", utc=True)
    stamps = stamps.dropna()
    return stamps.max() if len(stamps) else None


def _keys(df: pd.DataFrame) -> set[tuple]:
    return set(zip(df["git_url"], df["commit_hash"]))


def _key_series(df: pd.DataFrame) -> pd.Series:
    return pd.Series(list(zip(df["git_url"], df["commit_hash"])), index=df.index, dtype="object")


def _pair_set(vulns: pd.DataFrame) -> set[tuple]:
    return set(zip(vulns["affected_dependency"], vulns["vulnerability_id"]))


def compute(rung_dirs: list[Path | str], archive_dir: Path | str | None = None) -> dict:
    rungs = []
    for d in rung_dirs:
        d = Path(d)
        analyses, vulns, meta = _load_run(d)
        rungs.append({
            "dir": d,
            "analyses": analyses,
            "vulns": vulns,
            "meta": meta,
            "knowledge_date": _knowledge_date(meta),
        })
    if not rungs:
        raise ValueError("no rung dirs given")

    for r in rungs:
        if r["knowledge_date"] is None:
            log.warning("rung %s has no parseable knowledge date; sorting it first", r["dir"])
    # Stalest -> freshest; date-less rungs first, ties broken by path.
    rungs.sort(key=lambda r: (
        r["knowledge_date"] is not None,
        r["knowledge_date"] or pd.Timestamp(0, tz="UTC"),
        str(r["dir"]),
    ))

    shas = {
        ((r["meta"] or {}).get("api_sha"), (r["meta"] or {}).get("backend_sha"))
        for r in rungs
    }
    sha_mismatch = len(shas) > 1
    if sha_mismatch:
        log.warning(
            "api_sha/backend_sha differ across rungs (%s) — deltas are no longer "
            "attributable to the knowledge state alone", sorted(map(str, shas)),
        )

    common = set.intersection(*[_keys(r["analyses"]) for r in rungs])

    def _common_instances(r: dict) -> pd.DataFrame:
        v = r["vulns"]
        if len(v):
            v = v[_key_series(v).isin(common)]
        return v.drop_duplicates(INSTANCE_KEY)

    freshest = rungs[-1]
    fresh_v = _common_instances(freshest)
    fresh_pairs = _pair_set(fresh_v)

    out_rungs = []
    for r in rungs:
        v_common = _common_instances(r)
        pairs = _pair_set(v_common)
        union = pairs | fresh_pairs
        sev = v_common["severity_class"].astype(str).str.upper().value_counts()
        src = v_common["winning_source"].astype(str).value_counts()
        out_rungs.append({
            "dir": str(r["dir"]),
            "knowledge_date": str(r["knowledge_date"]) if r["knowledge_date"] is not None else None,
            "epss_rows": ((r["meta"] or {}).get("knowledge") or {}).get("epss_rows"),
            "n_analyses": int(len(r["analyses"])),
            "instances_total": int(len(r["vulns"])),
            "instances_common": int(len(v_common)),
            "severity_mix_common": {str(k): int(n) for k, n in sev.items()},
            "winning_source_mix_common": {str(k): int(n) for k, n in src.items()},
            "vs_freshest": {
                "instance_delta_common": int(len(v_common) - len(fresh_v)),
                "instance_delta_pct": (
                    (len(v_common) - len(fresh_v)) / len(fresh_v) * 100 if len(fresh_v) else None
                ),
                "jaccard_pairs": (len(pairs & fresh_pairs) / len(union)) if union else None,
            },
        })

    fidelity = None
    if archive_dir is not None:
        a_an, a_v, a_meta = _load_run(Path(archive_dir))
        a_date = _knowledge_date(a_meta)
        candidates = [
            r for r in rungs
            if r["knowledge_date"] is not None and a_date is not None
            and abs((r["knowledge_date"] - a_date).days) <= FIDELITY_TOLERANCE_DAYS
        ]
        if candidates:
            r = min(candidates, key=lambda r: abs(r["knowledge_date"] - a_date))
            shared = _keys(r["analyses"]) & _keys(a_an)
            rv = r["vulns"]
            if len(rv):
                rv = rv[_key_series(rv).isin(shared)]
            rv = rv.drop_duplicates(INSTANCE_KEY)
            av = a_v
            if len(av):
                av = av[_key_series(av).isin(shared)]
            av = av.drop_duplicates(INSTANCE_KEY)
            r_ids = pd.MultiIndex.from_frame(rv[INSTANCE_KEY])
            a_ids = pd.MultiIndex.from_frame(av[INSTANCE_KEY])
            n_union = len(r_ids.union(a_ids))
            fidelity = {
                "rung_dir": str(r["dir"]),
                "rung_knowledge_date": str(r["knowledge_date"]),
                "archive_knowledge_date": str(a_date),
                "shared_analyses": len(shared),
                "rung_only_analyses": len(_keys(r["analyses"]) - _keys(a_an)),
                "archive_only_analyses": len(_keys(a_an) - _keys(r["analyses"])),
                "rung_instances": int(len(rv)),
                "archive_instances": int(len(av)),
                "instance_delta_pct": ((len(rv) - len(av)) / len(av) * 100) if len(av) else None,
                "instance_jaccard": (len(r_ids.intersection(a_ids)) / n_union) if n_union else None,
            }
        else:
            log.info(
                "no rung within %dd of the archive knowledge date (%s) — fidelity check skipped",
                FIDELITY_TOLERANCE_DAYS, a_date,
            )

    return {
        "meta": {
            "rung_dirs": [str(r["dir"]) for r in rungs],
            "freshest": str(freshest["dir"]),
            "common_analyses": len(common),
            "sha_mismatch": sha_mismatch,
            "shas": {
                str(r["dir"]): {
                    "api_sha": (r["meta"] or {}).get("api_sha"),
                    "backend_sha": (r["meta"] or {}).get("backend_sha"),
                }
                for r in rungs
            },
        },
        "rungs": out_rungs,
        "fidelity": fidelity,
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--rungs", type=str, default="data-ladder/rung-*",
        help="glob of rung data dirs, each with tables/ built by `collect` "
        "(relative globs resolve against the experiment root)",
    )
    ap.add_argument("--archive", type=Path, default=ROOT / "data" / "archive-run-2026-06-snapshot")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "tables" / "ladder_dose_response.json")
    args = ap.parse_args()

    pattern = args.rungs if Path(args.rungs).is_absolute() else str(ROOT / args.rungs)
    rung_dirs = sorted(Path(p) for p in glob.glob(pattern) if Path(p).is_dir())
    if not rung_dirs:
        raise SystemExit(f"no rung dirs match {args.rungs!r}")
    archive = args.archive if (args.archive / "tables").is_dir() else None
    if archive is None:
        log.warning("archive tables not found at %s — fidelity check skipped", args.archive)

    out = compute(rung_dirs, archive_dir=archive)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(out, open(args.out, "w"), indent=1, default=str)
    print(f"wrote {args.out}")
    print(
        f"{len(out['rungs'])} rungs | common completed analyses: "
        f"{out['meta']['common_analyses']}"
        + (" | WARNING: api/backend SHAs differ across rungs" if out["meta"]["sha_mismatch"] else "")
    )
    for r in out["rungs"]:
        d = r["vs_freshest"]
        delta = "-" if d["instance_delta_pct"] is None else f"{d['instance_delta_pct']:+.2f}%"
        jac = "-" if d["jaccard_pairs"] is None else f"{d['jaccard_pairs']:.3f}"
        print(
            f"  {r['dir']}  k={r['knowledge_date']}  n={r['n_analyses']}  "
            f"common instances={r['instances_common']}  vs freshest: {delta}  "
            f"pair-jaccard={jac}"
        )
    if out["fidelity"] is not None:
        f = out["fidelity"]
        jac = "-" if f["instance_jaccard"] is None else f"{f['instance_jaccard']:.3f}"
        print(
            f"fidelity vs archive: {f['rung_dir']} shared={f['shared_analyses']} "
            f"instances {f['rung_instances']} vs {f['archive_instances']} "
            f"jaccard={jac}"
        )


if __name__ == "__main__":
    main()
