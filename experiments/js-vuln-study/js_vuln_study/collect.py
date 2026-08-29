"""Flatten raw plugin JSON blobs into tidy Parquet tables for analysis.

Two long-format tables are emitted under `<study>/tables/`:

* `analyses.parquet`: one row per completed (project, snapshot) scan, with
  summary counts pulled from the SBOM and vuln-finder blobs.
* `vulns.parquet`: one row per (analysis, vulnerability), including
  severity, EPSS, conflict flag, source winner.

Per-dependency rows and per-step dispatch telemetry are not materialised:
nothing downstream reads them, and the study's canonical recipe never
produced the former even before this simplification.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .config import Study
from .manifest import normalize_status, read as read_manifest

log = logging.getLogger(__name__)


def coverage_report(study: Study) -> dict[str, int]:
    """Bucket every manifest row by state and write coverage_dropped.csv for
    the non-`done` rows. Counts sum to the manifest size (minus the '*'
    skip-sentinel rows, which are pre-submission markers, not attempts)."""
    rows = read_manifest(study.manifest_path)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.state] = counts.get(r.state, 0) + 1

    dropped = [r for r in rows if r.state != "done"]
    if dropped:
        tables_dir = study.tables_dir
        tables_dir.mkdir(parents=True, exist_ok=True)
        pd.DataFrame([
            {
                "npm_name": r.npm_name, "git_url": r.git_url, "snapshot_date": r.snapshot_date,
                "state": r.state, "server_status": r.server_status, "error": r.error,
                "attempts": r.attempts,
            }
            for r in dropped
        ]).to_csv(tables_dir / "coverage_dropped.csv", index=False)
    log.info("coverage (%d attempted): %s", len(rows), counts)
    return counts


def _copy_run_meta(study: Study) -> None:
    """Copy the latest run_meta record next to the tables, and warn when the
    manifest mixes runs submitted under differing knowledge-DB snapshots."""
    path = study.run_meta_path
    if not path.exists():
        log.warning("no run_meta.jsonl - provenance unknown for these tables")
        return
    metas = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not metas:
        return
    study.tables_dir.mkdir(parents=True, exist_ok=True)
    (study.tables_dir / "run_meta.json").write_text(json.dumps(metas[-1], indent=2), encoding="utf-8")
    snapshots = {
        tuple(sorted(ks.items()))
        for m in metas
        if isinstance(ks := (m.get("knowledge") or {}).get("knowledge_sources"), dict)
    }
    if len(snapshots) > 1:
        log.warning(
            "manifest spans %d distinct knowledge-DB snapshots - vuln counts are "
            "not strictly comparable across runs (see %s)", len(snapshots), path,
        )


def _load_blob(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("invalid json at %s", path)
        return None
    # The /result endpoint returns the Result entity: {id, analysis_id,
    # plugin, result: {...}, created_on}. Unwrap the payload once if present.
    if isinstance(raw, dict) and isinstance(raw.get("result"), dict):
        return raw["result"]
    return raw


def _walk_workspaces(blob: Any) -> Iterable[tuple[str, dict]]:
    if not isinstance(blob, dict):
        return
    ws = blob.get("workspaces") or {}
    if isinstance(ws, dict):
        for name, payload in ws.items():
            if isinstance(payload, dict):
                yield name, payload


def _get_package_manager(sbom: Any) -> str | None:
    if not isinstance(sbom, dict):
        return None
    info = sbom.get("analysis_info") or {}
    return info.get("package_manager") if isinstance(info, dict) else None


def _match_vuln(v: dict, key: str) -> dict:
    m = v.get(key)
    if isinstance(m, dict):
        vuln = m.get("Vulnerability")
        if isinstance(vuln, dict):
            return vuln
    return {}


def _disclosure_dates(v: dict) -> tuple[str | None, str | None, str | None]:
    """(published, modified, withdrawn), preferring NVD, then OSV, then GCVE."""
    nvd = _match_vuln(v, "NVDMatch")
    osv = _match_vuln(v, "OSVMatch")
    gcve = _match_vuln(v, "GCVEMatch")
    published = nvd.get("Published") or osv.get("published") or gcve.get("datePublished")
    modified = nvd.get("LastModified") or osv.get("modified") or gcve.get("dateUpdated")
    withdrawn = osv.get("withdrawn")
    return (published or None, modified or None, withdrawn or None)


def _count_severity_classes(rows: list[dict]) -> dict[str, int]:
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for r in rows:
        sev = r.get("severity_class")
        if sev and str(sev).lower() in buckets:
            buckets[str(sev).lower()] += 1
    return buckets


def build_tables(study: Study) -> None:
    """Flatten raw blobs into analyses.parquet and vulns.parquet."""
    coverage_report(study)
    rows = read_manifest(study.manifest_path)
    tables_dir = study.tables_dir
    tables_dir.mkdir(parents=True, exist_ok=True)
    _copy_run_meta(study)

    analyses_rows: list[dict] = []
    vuln_rows: list[dict] = []

    for rec in rows:
        if rec.state != "done":
            continue
        aid, pid = rec.analysis_id, rec.project_id
        if not aid or not pid:
            continue
        root = study.raw_dir / pid / aid
        sbom = _load_blob(root / "js-sbom.json")
        vfind = _load_blob(root / "vuln-finder.json")

        summary = {
            "analysis_id": aid, "project_id": pid, "npm_name": rec.npm_name,
            "tier": rec.tier, "rank": rec.rank, "git_url": rec.git_url,
            "snapshot_date": rec.snapshot_date, "commit_hash": rec.commit_hash,
            "committed_at": rec.committed_at,
        }

        pm_for_analysis = _get_package_manager(sbom)
        dep_count, direct_count, transitive_count = 0, 0, 0
        dev_count, prod_count = 0, 0
        for _, ws in _walk_workspaces(sbom):
            deps_by_name = ws.get("dependencies") or {}
            if not isinstance(deps_by_name, dict):
                continue
            for versions in deps_by_name.values():
                if not isinstance(versions, dict):
                    continue
                for flags in versions.values():
                    if not isinstance(flags, dict):
                        continue
                    dep_count += 1
                    direct_count += bool(flags.get("Direct"))
                    transitive_count += bool(flags.get("Transitive"))
                    dev_count += bool(flags.get("Dev"))
                    prod_count += bool(flags.get("Prod"))

        total_vulns, vulnerable_deps = 0, set()
        direct_vulns, transitive_vulns = 0, 0
        per_analysis_vulns: list[dict] = []
        for ws_name, ws in _walk_workspaces(vfind):
            vulns = ws.get("Vulnerabilities") or []
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                total_vulns += 1
                dep_name = v.get("AffectedDependency")
                if dep_name:
                    vulnerable_deps.add(dep_name)
                if v.get("DirectDependency"):
                    direct_vulns += 1
                else:
                    transitive_vulns += 1
                sev = v.get("Severity") or {}
                epss = v.get("EPSS") or {}
                conflict = v.get("Conflict") or {}
                published, modified, withdrawn = _disclosure_dates(v)
                row = {
                    **summary,
                    "workspace": ws_name,
                    "vulnerability_id": v.get("VulnerabilityId"),
                    "affected_dependency": dep_name,
                    "affected_version": v.get("AffectedVersion"),
                    "severity_class": sev.get("SeverityClass"),
                    "severity_score": sev.get("Severity"),
                    "severity_vector": sev.get("Vector"),
                    "impact": sev.get("Impact"),
                    "exploitability": sev.get("Exploitability"),
                    "epss_score": epss.get("Score") if isinstance(epss, dict) else None,
                    "epss_percentile": epss.get("Percentile") if isinstance(epss, dict) else None,
                    "conflict_flag": conflict.get("ConflictFlag") if isinstance(conflict, dict) else None,
                    "winning_source": conflict.get("ConflictWinner") if isinstance(conflict, dict) else None,
                    "direct_dependency": bool(v.get("DirectDependency")),
                    "published_date": published,
                    "modified_date": modified,
                    "withdrawn_date": withdrawn,
                }
                vuln_rows.append(row)
                per_analysis_vulns.append(row)

        severity_counts = _count_severity_classes(per_analysis_vulns)
        analyses_rows.append({
            **summary,
            "run_id": rec.run_id,
            "total_dependencies": dep_count,
            "direct_dependencies": direct_count,
            "transitive_dependencies": transitive_count,
            "dev_dependencies": dev_count,
            "prod_dependencies": prod_count,
            "package_manager": pm_for_analysis,
            "total_vulnerabilities": total_vulns,
            "vulnerable_dependencies": len(vulnerable_deps),
            "direct_vulnerabilities": direct_vulns,
            "transitive_vulnerabilities": transitive_vulns,
            "n_critical": severity_counts["critical"],
            "n_high": severity_counts["high"],
            "n_medium": severity_counts["medium"],
            "n_low": severity_counts["low"],
            "n_none": severity_counts["none"],
        })

    analyses_df = pd.DataFrame(analyses_rows)
    vulns_df = pd.DataFrame(vuln_rows)
    analyses_df.to_parquet(tables_dir / "analyses.parquet", index=False)
    vulns_df.to_parquet(tables_dir / "vulns.parquet", index=False)
    log.info("wrote analyses=%d vulns=%d to %s", len(analyses_df), len(vulns_df), tables_dir)
