"""Cross-scanner triangulation: CodeClarity vs `npm audit` vs `osv-scanner`.

Reads the local parquet tables plus the configured raw-content endpoint
(GH_RAW_BASE, default raw.githubusercontent.com) only — it never talks to the
CodeClarity API. For a stratified subsample of HEAD analyses
(tercile of total_vulnerabilities × package_manager), it re-fetches each
project's package.json + lockfile at the exact analysed commit, runs the two
independent scanners on it, normalises everything to (package_name, CVE)
pairs, and reports pairwise set overlap.

Outputs (default under data/tables/):
  * triangulation.parquet        — row_type="pair": one row per (project,
    scanner pair) with set sizes, intersection, union, jaccard, a_only/b_only;
    row_type="project": one row per project with CodeClarity-vs-scanner-union
    counts (codeclarity_only / scanner_only / recall_vs_union).
  * triangulation_pairs.json     — the raw per-project pair sets, for audit.

Threats to validity (report results per lockfile type):
  * `npm audit` cannot read yarn.lock / pnpm-lock.yaml, so yarn/pnpm projects
    are osv-scanner-only comparisons — per-pair summaries mix lockfile
    populations unless split by `lockfile`.
  * Scanners disagree on advisory sourcing (GHSA vs OSV vs NVD) and alias
    completeness; findings with no CVE alias (GHSA-only) cannot be compared
    and are counted in the `*_unmapped` columns instead of the pair sets.
  * npm audit's `via` entries attribute advisories to the *vulnerable*
    package, which usually — but not always — matches CodeClarity's
    affected_dependency naming; names are lowercased before comparison.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from itertools import combinations
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pandas as pd

log = logging.getLogger(__name__)

# Env-overridable (GH_RAW_BASE), read once at import; empty/unset falls through
# to the canonical host, trailing slashes stripped — same contract as sample.py.
RAW_GITHUB = (os.environ.get("GH_RAW_BASE") or "https://raw.githubusercontent.com").rstrip("/")
LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]
NPM_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
SCAN_TIMEOUT = 120  # seconds, per scanner per project
INSTALL_TIMEOUT = 300  # seconds, one-shot `go install` of osv-scanner

OSV_MODULES = [
    "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
    "github.com/google/osv-scanner/cmd/osv-scanner@latest",  # v1 fallback
]


def _auth_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def parse_owner_repo(git_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a git remote URL (https or ssh), any host."""
    url = str(git_url).strip()
    if "://" not in url:
        # scp-style ssh remote (git@host:owner/repo.git) has no scheme — give
        # it one urlparse understands; anything else is a scheme-less https URL.
        m = re.match(r"^(?:[\w.+-]+@)?([^/:@]+):(.*)$", url)
        url = f"ssh://{m.group(1)}/{m.group(2)}" if m else f"https://{url}"
    parts = [p for p in urlparse(url).path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    return (owner, repo) if owner and repo else None


# --------------------------------------------------------------------------- #
# Subsample selection
# --------------------------------------------------------------------------- #

def select_projects(analyses: pd.DataFrame, n: int) -> pd.DataFrame:
    """Stratified deterministic subsample of HEAD rows.

    Strata are tercile-of-total_vulnerabilities × package_manager; projects
    are drawn round-robin across strata (sorted stratum labels), npm_name
    order within each stratum, until `n` are picked or strata are exhausted.
    """
    head = analyses[analyses["snapshot_date"] == "HEAD"].copy()
    head = head.sort_values("npm_name", kind="stable").reset_index(drop=True)
    if head.empty:
        return head
    # rank(method="first") keeps qcut deterministic despite heavy ties (zeros).
    ranks = head["total_vulnerabilities"].rank(method="first")
    tercile = pd.qcut(ranks, min(3, len(head)), labels=False)
    head["stratum"] = (
        "T" + tercile.astype(int).astype(str)
        + "|" + head["package_manager"].fillna("UNKNOWN").astype(str)
    )

    queues = {label: list(g.index) for label, g in head.groupby("stratum", sort=True)}
    picked: list[int] = []
    while len(picked) < n and any(queues.values()):
        for label in sorted(queues):
            if queues[label] and len(picked) < n:
                picked.append(queues[label].pop(0))
    return head.loc[picked]


# --------------------------------------------------------------------------- #
# GitHub raw fetch
# --------------------------------------------------------------------------- #

def _fetch(http: httpx.Client, path: str) -> bytes | None:
    r = http.get(path, headers=_auth_headers())
    if r.status_code == 200:
        return r.content
    if r.status_code != 404:
        log.warning("GET %s -> %s", path, r.status_code)
    return None


def fetch_repo_files(http: httpx.Client, owner: str, repo: str, sha: str,
                     dest: Path) -> str | None:
    """Fetch package.json + the first available lockfile at `sha` into `dest`.

    Returns the lockfile name, or None when no lockfile is fetchable. A
    missing package.json is replaced by a minimal stub (npm audit needs one
    next to the lockfile).
    """
    base = f"/{owner}/{repo}/{sha}"
    lock_name = None
    for name in LOCKFILES:
        blob = _fetch(http, f"{base}/{name}")
        if blob is not None:
            lock_name = name
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_bytes(blob)
            break
    if lock_name is None:
        return None
    pkg = _fetch(http, f"{base}/package.json")
    if pkg is None:
        pkg = json.dumps({"name": "triangulation-stub", "version": "0.0.0"}).encode()
    (dest / "package.json").write_bytes(pkg)
    return lock_name


# --------------------------------------------------------------------------- #
# Scanners
# --------------------------------------------------------------------------- #

def _run_json(cmd: list[str], cwd: Path | None = None,
              timeout: int = SCAN_TIMEOUT) -> dict | None:
    """Run a scanner and parse its stdout as JSON, tolerating non-zero exit
    codes that still produce JSON (npm audit exits 1 when vulns are found)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning("%s timed out after %ss", cmd[0], timeout)
        return None
    except FileNotFoundError:
        log.warning("%s not found on PATH", cmd[0])
        return None
    out = proc.stdout.strip()
    if out:
        # Some npm versions prefix warnings before the JSON document.
        for candidate in (out, out[out.find("{"):] if "{" in out else ""):
            if not candidate:
                continue
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    log.warning(
        "%s produced no parseable JSON (rc=%d): %s",
        " ".join(cmd[:2]), proc.returncode, (proc.stderr or "").strip()[:200],
    )
    return None


def find_osv_scanner() -> str | None:
    path = shutil.which("osv-scanner")
    if path:
        return path
    gobin = os.environ.get("GOBIN") or str(
        Path(os.environ.get("GOPATH", str(Path.home() / "go"))) / "bin"
    )
    candidate = Path(gobin) / "osv-scanner"
    return str(candidate) if candidate.exists() else None


def ensure_osv_scanner() -> str | None:
    """Locate osv-scanner, attempting a one-shot `go install` (v2 then v1)."""
    found = find_osv_scanner()
    if found:
        return found
    if not shutil.which("go"):
        log.warning("osv-scanner absent and no Go toolchain — npm-audit-only run")
        return None
    for module in OSV_MODULES:
        log.info("installing %s (once, %ss timeout)", module, INSTALL_TIMEOUT)
        try:
            proc = subprocess.run(
                ["go", "install", module],
                capture_output=True, text=True, timeout=INSTALL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log.warning("go install %s timed out", module)
            continue
        if proc.returncode == 0:
            found = find_osv_scanner()
            if found:
                return found
        else:
            log.warning("go install %s failed: %s", module, (proc.stderr or "")[-200:])
    log.warning("osv-scanner could not be installed — npm-audit-only run")
    return None


# --------------------------------------------------------------------------- #
# Normalisation to (package_name, CVE) pairs
# --------------------------------------------------------------------------- #

def codeclarity_pairs(vulns: pd.DataFrame, analysis_id: str) -> set[tuple[str, str]]:
    sub = vulns[vulns["analysis_id"] == analysis_id]
    pairs = set()
    for dep, vid in zip(sub["affected_dependency"], sub["vulnerability_id"]):
        if isinstance(vid, str) and vid.startswith("CVE-") and dep:
            pairs.add((str(dep).lower(), vid))
    return pairs


def npm_audit_pairs(audit: dict) -> tuple[set[tuple[str, str]], int]:
    """(pairs, unmapped) from `npm audit --json` — walk via[] advisory objects,
    pulling CVE ids from their cve/cves/cwe arrays and the advisory url."""
    pairs: set[tuple[str, str]] = set()
    unmapped = 0
    for pkg, entry in (audit.get("vulnerabilities") or {}).items():
        if not isinstance(entry, dict):
            continue
        for via in entry.get("via") or []:
            if not isinstance(via, dict):
                continue  # string via = pointer to another vulnerable package
            name = str(via.get("name") or pkg).lower()
            cves: set[str] = set()
            for field in ("cve", "cves", "cwe", "url"):
                val = via.get(field)
                for s in val if isinstance(val, list) else [val]:
                    if isinstance(s, str):
                        cves.update(CVE_RE.findall(s))
            if cves:
                pairs.update((name, c) for c in cves)
            else:
                unmapped += 1
    return pairs, unmapped


def osv_pairs(scan: dict) -> tuple[set[tuple[str, str]], int]:
    """(pairs, unmapped) from `osv-scanner --format json` results."""
    pairs: set[tuple[str, str]] = set()
    unmapped = 0
    for res in scan.get("results") or []:
        for p in res.get("packages") or []:
            name = str((p.get("package") or {}).get("name") or "").lower()
            for v in p.get("vulnerabilities") or []:
                ids = [
                    a for a in (v.get("aliases") or [])
                    if isinstance(a, str) and a.startswith("CVE-")
                ]
                vid = v.get("id")
                if not ids and isinstance(vid, str) and vid.startswith("CVE-"):
                    ids = [vid]
                if ids and name:
                    pairs.update((name, c) for c in ids)
                else:
                    unmapped += 1
    return pairs, unmapped


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def run_triangulation(data_dir: Path, n: int, out: Path, dry_run: bool = False) -> int:
    tables = data_dir / "tables"
    analyses_path = tables / "analyses.parquet"
    vulns_path = tables / "vulns.parquet"
    if not analyses_path.exists() or not vulns_path.exists():
        log.error("missing %s / %s — run `python run.py collect` first",
                  analyses_path, vulns_path)
        return 1

    analyses = pd.read_parquet(analyses_path)
    vulns = pd.read_parquet(vulns_path)
    picked = select_projects(analyses, n)
    if picked.empty:
        log.error("no HEAD rows in %s — nothing to triangulate", analyses_path)
        return 1

    log.info("selected %d/%d HEAD projects across %d strata",
             len(picked), int((analyses["snapshot_date"] == "HEAD").sum()),
             picked["stratum"].nunique())
    print(picked[["npm_name", "stratum", "package_manager",
                  "total_vulnerabilities", "commit_hash"]].to_string(index=False))
    if dry_run:
        return 0

    osv_bin = ensure_osv_scanner()
    npm_bin = shutil.which("npm")
    if not npm_bin:
        log.warning("npm not on PATH — npm-audit comparisons will be skipped")

    rows: list[dict] = []
    raw_sets: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="js-vuln-triangulate-") as tmp, \
            httpx.Client(base_url=RAW_GITHUB, timeout=30.0,
                         follow_redirects=True) as http:
        for rec in picked.itertuples(index=False):
            owner_repo = parse_owner_repo(rec.git_url)
            sha = rec.commit_hash
            if not owner_repo or not isinstance(sha, str) or not sha:
                log.warning("skipping %s: unparseable git_url or missing commit_hash",
                            rec.npm_name)
                continue
            owner, repo = owner_repo
            dest = Path(tmp) / re.sub(r"[^A-Za-z0-9._-]", "_", rec.npm_name)
            lock = fetch_repo_files(http, owner, repo, sha, dest)
            if lock is None:
                log.warning("skipping %s: no lockfile fetchable at %s/%s@%.9s",
                            rec.npm_name, owner, repo, sha)
                continue

            sets: dict[str, set[tuple[str, str]]] = {
                "codeclarity": codeclarity_pairs(vulns, rec.analysis_id),
            }
            unmapped = {"npm_audit": None, "osv": None}
            if npm_bin and lock in NPM_LOCKFILES:
                audit = _run_json(
                    [npm_bin, "audit", "--package-lock-only", "--json"], cwd=dest,
                )
                if audit is not None:
                    sets["npm_audit"], unmapped["npm_audit"] = npm_audit_pairs(audit)
            if osv_bin:
                scan = _run_json(
                    [osv_bin, "--format", "json", "--lockfile", str(dest / lock)],
                )
                if scan is not None:
                    sets["osv"], unmapped["osv"] = osv_pairs(scan)

            log.info("%s [%s]: %s", rec.npm_name, lock,
                     {k: len(v) for k, v in sets.items()})
            base = {
                "npm_name": rec.npm_name,
                "project_id": rec.project_id,
                "analysis_id": rec.analysis_id,
                "commit_hash": sha,
                "lockfile": lock,
                "stratum": rec.stratum,
                "scanners_run": ",".join(sorted(sets)),
                "npm_audit_unmapped": unmapped["npm_audit"],
                "osv_unmapped": unmapped["osv"],
            }
            for a, b in combinations(sorted(sets), 2):
                inter = len(sets[a] & sets[b])
                union = len(sets[a] | sets[b])
                rows.append({
                    **base, "row_type": "pair", "pair": f"{a}_vs_{b}",
                    "n_a": len(sets[a]), "n_b": len(sets[b]),
                    "n_intersection": inter, "n_union": union,
                    "jaccard": (inter / union) if union else float("nan"),
                    "a_only": len(sets[a] - sets[b]),
                    "b_only": len(sets[b] - sets[a]),
                })
            others = set().union(*(v for k, v in sets.items() if k != "codeclarity")) \
                if len(sets) > 1 else set()
            cc = sets["codeclarity"]
            union_all = cc | others
            rows.append({
                **base, "row_type": "project", "pair": "codeclarity_vs_scanner_union",
                "n_a": len(cc), "n_b": len(others),
                "n_intersection": len(cc & others), "n_union": len(union_all),
                "jaccard": (len(cc & others) / len(union_all)) if union_all else float("nan"),
                "a_only": len(cc - others), "b_only": len(others - cc),
                "codeclarity_only": len(cc - others),
                "scanner_only": len(others - cc),
                "recall_vs_union": (len(cc) / len(union_all)) if union_all else float("nan"),
            })
            raw_sets[rec.npm_name] = {
                "commit_hash": sha,
                "lockfile": lock,
                **{k: sorted(map(list, v)) for k, v in sets.items()},
            }

    if not rows:
        log.error("no project could be triangulated (lockfiles unfetchable?)")
        return 1

    df = pd.DataFrame(rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    pairs_path = out.parent / "triangulation_pairs.json"
    pairs_path.write_text(json.dumps(raw_sets, indent=2), encoding="utf-8")
    log.info("wrote %d rows to %s (raw sets: %s)", len(df), out, pairs_path)

    pair_df = df[df["row_type"] == "pair"]
    if not pair_df.empty:
        print("\nMean jaccard per scanner pair (split by lockfile type — npm audit")
        print("cannot read yarn/pnpm locks, so pooled numbers mix populations):")
        print(pair_df.groupby(["pair", "lockfile"])["jaccard"]
              .agg(["count", "mean"]).round(3).to_string())
    proj_df = df[df["row_type"] == "project"]
    pooled = proj_df["n_a"].sum() / max(proj_df["n_union"].sum(), 1)
    print(f"\nCodeClarity recall vs scanner union: mean/project = "
          f"{proj_df['recall_vs_union'].mean():.3f}, pooled = {pooled:.3f} "
          f"(n={len(proj_df)} projects)")
    if osv_bin is None:
        print("NOTE: osv-scanner unavailable — npm-audit-only comparison, "
              "yarn/pnpm projects contributed no scanner pairs.")
    return 0
