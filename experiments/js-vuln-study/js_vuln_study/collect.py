"""Flatten raw plugin JSON blobs into tidy Parquet tables for analysis.

Three long-format tables are emitted under `data/tables/`:

* `analyses.parquet`   — one row per (project, snapshot) scan with summary
                         metrics pulled from the SBOM, vuln, patching blobs.
* `vulns.parquet`      — one row per (analysis, vulnerability) including
                         severity, EPSS, conflict flag, source winner.
* `dependencies.parquet` — one row per (analysis, dependency) with
                           package_manager, direct/transitive flags, release
                           date, deprecated/outdated flags.

The schemas are deliberately denormalized — joining back through `analysis_id`
is cheap at research-dataset scale and keeps the post-processing notebooks
simple.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

log = logging.getLogger(__name__)


def _read_manifest(data_dir: Path) -> list[dict]:
    path = data_dir / "manifest.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(l)
        for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]


def _load_blob(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("invalid json at %s", path)
        return None
    # The /result endpoint returns the Result entity: { id, analysis_id, plugin,
    # result: {...}, created_on }. Unwrap the payload once if present.
    if isinstance(raw, dict) and "result" in raw and isinstance(raw["result"], dict):
        return raw["result"]
    return raw


def _walk_workspaces(blob: Any) -> Iterable[tuple[str, dict]]:
    """Yield (workspace_name, workspace_payload) from a plugin result blob.

    All four plugins share the outer shape:
        { "workspaces": { "<name>": { ... } }, "analysis_info": { ... } }
    """
    if not isinstance(blob, dict):
        return
    ws = blob.get("workspaces") or blob.get("Workspaces") or {}
    if isinstance(ws, dict):
        for name, payload in ws.items():
            if isinstance(payload, dict):
                yield name, payload


def _get_package_manager(sbom: Any) -> str | None:
    if not isinstance(sbom, dict):
        return None
    info = sbom.get("analysis_info") or {}
    return info.get("package_manager") if isinstance(info, dict) else None


def _count_severity_classes(rows: list[dict]) -> dict[str, int]:
    """Count per-analysis severity classes from already-flattened vuln rows."""
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for r in rows:
        sev = r.get("severity_class")
        if not sev:
            continue
        key = str(sev).lower()
        if key in buckets:
            buckets[key] += 1
    return buckets


def build_tables(data_dir: Path) -> None:
    manifest = _read_manifest(data_dir)
    raw_root = data_dir / "raw"
    tables_dir = data_dir / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)

    analyses_rows: list[dict] = []
    vuln_rows: list[dict] = []
    dep_rows: list[dict] = []

    for rec in manifest:
        if rec.get("status") not in {"completed", "success"}:
            continue
        aid = rec.get("analysis_id")
        pid = rec.get("project_id")
        if not aid or not pid:
            continue
        root = raw_root / pid / aid
        sbom = _load_blob(root / "js-sbom.json")
        vfind = _load_blob(root / "vuln-finder.json")
        lic = _load_blob(root / "license-finder.json")

        summary = {
            "analysis_id": aid,
            "project_id": pid,
            "npm_name": rec["npm_name"],
            "tier": rec["tier"],
            "rank": rec["rank"],
            "git_url": rec["git_url"],
            "snapshot_date": rec["snapshot_date"],
            "commit_hash": rec["commit_hash"],
            "committed_at": rec["committed_at"],
        }

        # js-sbom shape: workspaces[ws]["dependencies"][name][version] -> flags
        # (Versions struct has no JSON tags → Go marshals fields as PascalCase.)
        pm_for_analysis = _get_package_manager(sbom)
        dep_count, direct_count, transitive_count = 0, 0, 0
        dev_count, prod_count = 0, 0
        for ws_name, ws in _walk_workspaces(sbom):
            deps_by_name = ws.get("dependencies") or {}
            if not isinstance(deps_by_name, dict):
                continue
            for dep_name, versions in deps_by_name.items():
                if not isinstance(versions, dict):
                    continue
                for version, flags in versions.items():
                    if not isinstance(flags, dict):
                        continue
                    dep_count += 1
                    direct = bool(flags.get("Direct"))
                    transitive = bool(flags.get("Transitive"))
                    dev = bool(flags.get("Dev"))
                    prod = bool(flags.get("Prod"))
                    if direct:
                        direct_count += 1
                    if transitive:
                        transitive_count += 1
                    if dev:
                        dev_count += 1
                    if prod:
                        prod_count += 1
                    dep_rows.append({
                        **summary,
                        "workspace": ws_name,
                        "name": dep_name,
                        "version": version,
                        "package_manager": pm_for_analysis,
                        "direct": direct,
                        "transitive": transitive,
                        "dev": dev,
                        "prod": prod,
                        "optional": bool(flags.get("Optional")),
                        "bundled": bool(flags.get("Bundled")),
                        "licenses": flags.get("Licenses") or [],
                    })

        total_vulns, vulnerable_deps = 0, set()
        direct_vulns, transitive_vulns = 0, 0
        per_analysis_vulns: list[dict] = []
        for ws_name, ws in _walk_workspaces(vfind):
            vulns = ws.get("Vulnerabilities") or ws.get("vulnerabilities") or []
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                total_vulns += 1
                dep_name = v.get("AffectedDependency") or v.get("affected_dependency")
                if dep_name:
                    vulnerable_deps.add(dep_name)
                if v.get("DirectDependency") or v.get("direct_dependency"):
                    direct_vulns += 1
                else:
                    transitive_vulns += 1
                sev = (v.get("Severity") or {})
                epss = v.get("EPSS") or {}
                conflict = v.get("Conflict") or {}
                row = {
                    **summary,
                    "workspace": ws_name,
                    "vulnerability_id": v.get("VulnerabilityId") or v.get("vulnerability_id"),
                    "affected_dependency": dep_name,
                    "affected_version": v.get("AffectedVersion") or v.get("affected_version"),
                    "severity_class": sev.get("SeverityClass"),
                    "severity_score": sev.get("Severity"),
                    "severity_vector": sev.get("Vector"),
                    "impact": sev.get("Impact"),
                    "exploitability": sev.get("Exploitability"),
                    "epss_score": epss.get("Score") if isinstance(epss, dict) else None,
                    "epss_percentile": epss.get("Percentile") if isinstance(epss, dict) else None,
                    "conflict_flag": conflict.get("ConflictFlag") if isinstance(conflict, dict) else None,
                    "winning_source": conflict.get("WinningSource") if isinstance(conflict, dict) else None,
                    "direct_dependency": bool(v.get("DirectDependency") or v.get("direct_dependency")),
                }
                vuln_rows.append(row)
                per_analysis_vulns.append(row)

        severity_counts = _count_severity_classes(per_analysis_vulns)

        # js-patching is temporarily disabled — known bug, data untrustworthy.

        analyses_rows.append({
            **summary,
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
    deps_df = pd.DataFrame(dep_rows)

    analyses_df.to_parquet(tables_dir / "analyses.parquet", index=False)
    vulns_df.to_parquet(tables_dir / "vulns.parquet", index=False)
    deps_df.to_parquet(tables_dir / "dependencies.parquet", index=False)

    log.info(
        "wrote analyses=%d vulns=%d deps=%d to %s",
        len(analyses_df), len(vulns_df), len(deps_df), tables_dir,
    )
