"""Popularity-stratified npm sample.

The npm registry's `/-/v1/search` endpoint requires a text query and does not
expose a global "sort-by-popularity" firehose. We therefore query a broad seed
of common JS keywords, union the results, score each package by its npm-reported
popularity, then bucket into popularity tiers.

The sampler also verifies that each candidate repo commits a JS lockfile — a
project without `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` produces
zero resolved dependencies when scanned. The lockfile probe is deduplicated by
(owner, repo) to avoid re-hitting the GitHub API for each package of a monorepo.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

NPM_SEARCH = "https://registry.npmjs.com/-/v1/search"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
PAGE_SIZE = 250  # npm registry search hard cap per request
DOWNLOADS_BATCH = 100  # npm bulk downloads endpoint caps around this
GITHUB_RE = re.compile(
    r"(?:github\.com[:/])([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git|/|$)"
)
LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")

# Seed keywords cover common JS ecosystems without over-indexing any single
# domain. Each keyword's popularity-weighted search returns up to ~1000 packages;
# the union is deduped by name and re-ranked by npm popularity score.
SEED_KEYWORDS = [
    "javascript", "typescript", "node", "react", "vue", "angular", "svelte",
    "express", "fastify", "next", "nuxt", "test", "mock", "cli", "build",
    "webpack", "vite", "rollup", "babel", "eslint", "prettier", "util",
    "stream", "http", "fetch", "async", "date", "parse", "format", "json",
    "logger", "validate", "crypto", "auth", "database", "orm", "graphql",
]

TIER_BOUNDS = [
    ("top-100", 0, 100),
    ("top-1k", 100, 1_000),
    ("top-10k", 1_000, 10_000),
    ("long-tail", 10_000, 20_000),
]


@dataclass
class ProjectSpec:
    npm_name: str
    rank: int
    tier: str
    git_url: str
    github_owner: str
    github_repo: str
    default_branch: str


@dataclass
class _RepoInfo:
    default_branch: str
    has_lockfile: bool


def _normalize_github(repo_url: str) -> tuple[str, str] | None:
    m = GITHUB_RE.search(repo_url or "")
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    repo = repo.removesuffix(".git")
    return owner, repo


def _npm_search(
    http: httpx.Client,
    text: str,
    frm: int,
    size: int,
) -> list[dict[str, Any]]:
    """Call the npm registry search with exponential backoff on 429/5xx."""
    for attempt in range(6):
        r = http.get(
            NPM_SEARCH,
            params={
                "text": text,
                "from": frm,
                "size": size,
                "popularity": 1.0,
                "quality": 0.0,
                "maintenance": 0.0,
            },
        )
        if r.status_code == 200:
            return r.json().get("objects") or []
        if r.status_code == 429 or 500 <= r.status_code < 600:
            retry_after = r.headers.get("Retry-After")
            wait = max(5.0, float(retry_after)) if retry_after else 2.0 * (2 ** attempt)
            log.warning("npm registry %d; sleeping %.1fs", r.status_code, wait)
            time.sleep(wait)
            continue
        r.raise_for_status()
    log.error("npm registry gave up after retries for text=%r from=%d", text, frm)
    return []


def _fetch_downloads_json(http: httpx.Client, url: str) -> Any:
    """GET with retry for the npm downloads API. Returns parsed JSON or None."""
    for attempt in range(4):
        r = http.get(url)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return None
        if r.status_code == 404:
            return None
        if r.status_code == 429 or 500 <= r.status_code < 600:
            wait = 2.0 * (2 ** attempt)
            log.warning("downloads API %d; sleeping %.1fs", r.status_code, wait)
            time.sleep(wait)
            continue
        return None
    return None


def _fetch_weekly_downloads(
    names: list[str],
    sleep_bulk: float = 0.2,
    sleep_single: float = 0.05,
) -> dict[str, int]:
    """Query the npm downloads API for last-week counts.

    Unscoped packages batch at DOWNLOADS_BATCH per request (comma-separated).
    Scoped packages (`@scope/name`) aren't supported by the bulk endpoint,
    so they're queried individually. Missing packages map to 0.
    """
    out: dict[str, int] = {n: 0 for n in names}
    scoped = [n for n in names if n.startswith("@")]
    unscoped = [n for n in names if not n.startswith("@")]

    http = httpx.Client(timeout=30.0)
    try:
        for i in range(0, len(unscoped), DOWNLOADS_BATCH):
            batch = unscoped[i : i + DOWNLOADS_BATCH]
            url = f"{NPM_DOWNLOADS}/{','.join(batch)}"
            resp = _fetch_downloads_json(http, url)
            if isinstance(resp, dict):
                # Single-package response when len(batch)==1 returns a flat
                # {downloads, package, ...}; batch returns name-keyed dict.
                if "downloads" in resp and "package" in resp:
                    out[resp["package"]] = resp.get("downloads") or 0
                else:
                    for name in batch:
                        entry = resp.get(name)
                        if isinstance(entry, dict):
                            out[name] = entry.get("downloads") or 0
            if sleep_bulk:
                time.sleep(sleep_bulk)

        for name in scoped:
            url = f"{NPM_DOWNLOADS}/{name}"
            resp = _fetch_downloads_json(http, url)
            if isinstance(resp, dict):
                out[name] = resp.get("downloads") or 0
            if sleep_single:
                time.sleep(sleep_single)
    finally:
        http.close()
    return out


def _enrich_with_downloads(aggregated: dict[str, dict[str, Any]]) -> None:
    """Attach weekly download counts to each aggregated entry, in place.

    Already-enriched entries (containing a `downloads` key) are skipped so
    re-runs with a warm cache don't re-query every package.
    """
    missing = [n for n, e in aggregated.items() if "downloads" not in e]
    if not missing:
        return
    log.info("fetching weekly downloads for %d packages", len(missing))
    counts = _fetch_weekly_downloads(missing)
    for name, cnt in counts.items():
        aggregated[name]["downloads"] = cnt


def _gather_candidates(
    keywords: list[str],
    per_keyword: int = 500,
    sleep: float = 0.5,
) -> dict[str, dict[str, Any]]:
    """Query each keyword, aggregate by package name, keep the best popularity.

    Returns a dict mapping npm_name -> { package: meta, popularity: float }.
    The npm registry rate-limits aggressively (~20 req / min), so keep
    `per_keyword` modest and sleep between requests.

    `popularity` from this endpoint is unreliable (it returns 1.0 for almost
    every package); callers should enrich via `_enrich_with_downloads` and
    rank by weekly download count instead.
    """
    out: dict[str, dict[str, Any]] = {}
    http = httpx.Client(timeout=30.0)
    try:
        for kw in keywords:
            log.info("searching npm for keyword=%r", kw)
            fetched = 0
            while fetched < per_keyword:
                size = min(PAGE_SIZE, per_keyword - fetched)
                objects = _npm_search(http, kw, fetched, size)
                if not objects:
                    break
                for obj in objects:
                    pkg = obj.get("package") or {}
                    name = pkg.get("name")
                    if not name:
                        continue
                    pop = (
                        ((obj.get("score") or {}).get("detail") or {}).get("popularity")
                        or 0.0
                    )
                    prev = out.get(name)
                    if prev is None or pop > prev["popularity"]:
                        out[name] = {"package": pkg, "popularity": pop}
                fetched += len(objects)
                if sleep:
                    time.sleep(sleep)
    finally:
        http.close()
    log.info("gathered %d unique packages across %d keywords", len(out), len(keywords))
    return out


class RepoProber:
    """Verifies a GitHub repo exists, records its default branch, and (optionally)
    checks that it commits a JS lockfile.

    The probe is `/repos/{owner}/{repo}` (existence + default_branch) plus an
    optional `/contents/?ref={default_branch}` to scan root-level filenames.
    Results are cached by (owner, repo) — monorepos publish many packages from
    the same repo and we only need to probe once.

    Rate-limit responses surface as `RateLimitExhausted` so the caller can
    abort the sampling loop instead of sleeping through the window reset.
    """

    class RateLimitExhausted(RuntimeError):
        def __init__(self, reset_in: float):
            super().__init__(f"github rate limit exhausted; resets in {reset_in:.0f}s")
            self.reset_in = reset_in

    def __init__(
        self,
        client: httpx.Client,
        max_wait: float = 30.0,
        check_lockfile: bool = True,
        cache_path: Path | None = None,
    ) -> None:
        self._client = client
        self._cache: dict[tuple[str, str], _RepoInfo | None] = {}
        self._max_wait = max_wait
        self._check_lockfile = check_lockfile
        self._cache_path = cache_path
        self._cached_without_lockfile: set[tuple[str, str]] = set()
        if cache_path is not None and cache_path.exists():
            self._load_cache()

    def _load_cache(self) -> None:
        assert self._cache_path is not None
        loaded = 0
        for line in self._cache_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (rec["owner"], rec["repo"])
            branch = rec.get("default_branch")
            if branch is None:
                self._cache[key] = None
            else:
                self._cache[key] = _RepoInfo(
                    default_branch=branch,
                    has_lockfile=bool(rec.get("has_lockfile", False)),
                )
                if not rec.get("lockfile_checked", False):
                    self._cached_without_lockfile.add(key)
            loaded += 1
        log.info("loaded %d probe records from %s", loaded, self._cache_path)

    def _append_cache(
        self, key: tuple[str, str], info: _RepoInfo | None, lockfile_checked: bool
    ) -> None:
        if self._cache_path is None:
            return
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "owner": key[0],
            "repo": key[1],
            "default_branch": info.default_branch if info else None,
            "has_lockfile": info.has_lockfile if info else False,
            "lockfile_checked": lockfile_checked,
        }
        with self._cache_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def probe(self, owner: str, repo: str) -> _RepoInfo | None:
        """Return repo info, or None if the repo is missing / inaccessible."""
        key = (owner.lower(), repo.lower())
        if key in self._cache:
            cached = self._cache[key]
            # Cache entry predates lockfile-checking — re-probe just the
            # lockfile so we don't silently treat it as absent.
            if (
                cached is not None
                and self._check_lockfile
                and key in self._cached_without_lockfile
            ):
                headers = self._auth_headers()
                cached.has_lockfile = self._probe_lockfile(
                    owner, repo, cached.default_branch, headers
                )
                self._cached_without_lockfile.discard(key)
                self._append_cache(key, cached, lockfile_checked=True)
            return cached

        headers = self._auth_headers()
        meta_url = f"https://api.github.com/repos/{owner}/{repo}"
        r = self._retry_get(meta_url, headers)
        if r is None or r.status_code != 200:
            self._cache[key] = None
            self._append_cache(key, None, lockfile_checked=self._check_lockfile)
            return None
        try:
            meta = r.json()
        except Exception:
            self._cache[key] = None
            self._append_cache(key, None, lockfile_checked=self._check_lockfile)
            return None
        default_branch = meta.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            self._cache[key] = None
            self._append_cache(key, None, lockfile_checked=self._check_lockfile)
            return None

        has_lockfile = False
        if self._check_lockfile:
            has_lockfile = self._probe_lockfile(owner, repo, default_branch, headers)

        info = _RepoInfo(default_branch=default_branch, has_lockfile=has_lockfile)
        self._cache[key] = info
        self._append_cache(key, info, lockfile_checked=self._check_lockfile)
        return info

    @staticmethod
    def _auth_headers() -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _probe_lockfile(
        self, owner: str, repo: str, branch: str, headers: dict[str, str]
    ) -> bool:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/"
        r = self._retry_get(url, headers, params={"ref": branch})
        if r is None or r.status_code != 200:
            return False
        try:
            entries = r.json()
        except Exception:
            return False
        if not isinstance(entries, list):
            return False
        names = {e.get("name") for e in entries if isinstance(e, dict)}
        return any(lf in names for lf in LOCKFILES)

    def _retry_get(
        self,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
    ) -> httpx.Response | None:
        for attempt in range(3):
            r = self._client.get(url, headers=headers, params=params)
            if r.status_code in (200, 301, 302, 404):
                return r
            if r.status_code in (403, 429):
                reset = r.headers.get("X-RateLimit-Reset")
                retry_after = r.headers.get("Retry-After")
                if retry_after:
                    wait = float(retry_after)
                elif reset:
                    wait = max(1.0, float(reset) - time.time() + 2.0)
                else:
                    wait = 2.0 * (2 ** attempt)
                if wait > self._max_wait:
                    raise self.RateLimitExhausted(wait)
                log.warning("github %d; sleeping %.1fs", r.status_code, wait)
                time.sleep(wait)
                continue
            log.warning("unexpected github status %d for %s", r.status_code, url)
            return r
        return None


def _load_aggregate_cache(
    path: Path, keywords: list[str], per_keyword: int
) -> dict[str, dict[str, Any]] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if data.get("keywords") != keywords or data.get("per_keyword") != per_keyword:
        log.info("aggregate cache params changed — rebuilding")
        return None
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return None
    log.info("loaded %d packages from aggregate cache %s", len(packages), path)
    return packages


def _save_aggregate_cache(
    path: Path,
    keywords: list[str],
    per_keyword: int,
    packages: dict[str, dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "keywords": keywords,
            "per_keyword": per_keyword,
            "packages": packages,
        }),
        encoding="utf-8",
    )


def build_sample(
    per_tier: int = 100,
    seed: int = 42,
    max_rank: int = 20_000,
    output: Path | None = None,
    require_lockfile: bool = True,
    keywords: list[str] | None = None,
    per_keyword: int = 500,
    aggregate_cache: Path | None = None,
    probe_cache: Path | None = None,
) -> list[ProjectSpec]:
    """Build a popularity-stratified sample of npm packages with committed lockfiles.

    Strategy: run a popularity-weighted search per seed keyword, union the
    results (keeping the highest popularity score seen for each package),
    rank by popularity descending, drop repos without a lockfile, then assign
    each surviving package to one of four tiers by its final rank.
    """
    rng = random.Random(seed)
    kws = keywords or SEED_KEYWORDS

    if not os.environ.get("GITHUB_TOKEN"):
        log.warning(
            "GITHUB_TOKEN not set — repo probing is capped at 60/h "
            "unauthenticated and will abort after ~30 repos. Set a classic "
            "PAT with `public_repo` scope for a 5000/h budget.",
        )

    aggregated = None
    if aggregate_cache is not None:
        aggregated = _load_aggregate_cache(aggregate_cache, kws, per_keyword)
    if aggregated is None:
        aggregated = _gather_candidates(kws, per_keyword=per_keyword)

    # Score every package by real weekly downloads. npm's search endpoint
    # returns a uniform popularity=1 for almost every package, so without
    # this step the rank sort collapses to alphabetical and the "top-100"
    # tier fills up with obscure, lexicographically-early packages.
    _enrich_with_downloads(aggregated)
    if aggregate_cache is not None:
        _save_aggregate_cache(aggregate_cache, kws, per_keyword, aggregated)

    # Rank by weekly downloads descending. Ties broken by name for determinism.
    ranked = sorted(
        aggregated.items(),
        key=lambda kv: (-kv[1].get("downloads", 0), kv[0]),
    )[:max_rank]

    # Dedup by (owner, repo) before probing GitHub — monorepos publish many
    # packages from the same repo; we only need to check the lockfile once.
    by_repo: dict[tuple[str, str], list[tuple[int, str, dict[str, Any]]]] = {}
    repo_order: list[tuple[str, str]] = []
    for final_rank, (name, entry) in enumerate(ranked):
        meta = entry["package"]
        links = meta.get("links") or {}
        repo = links.get("repository") or meta.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url")
        parsed = _normalize_github(repo or "")
        if not parsed:
            continue
        key = (parsed[0].lower(), parsed[1].lower())
        if key not in by_repo:
            by_repo[key] = []
            repo_order.append(key)
        by_repo[key].append((final_rank, name, meta))

    log.info("ranked %d packages into %d unique repos", len(ranked), len(repo_order))

    # Probe repos lazily in rank order and stop as soon as every tier target
    # is met. For small runs (per_tier=5) this checks ~20-50 repos instead of
    # the full 9k — well within GitHub's 5000/h budget per hour.
    by_tier: dict[str, list[ProjectSpec]] = {name: [] for name, _, _ in TIER_BOUNDS}

    def _tier_targets() -> dict[str, int]:
        # Over-sample non-top tiers so random.sample has headroom.
        return {
            name: (per_tier if name == "top-100" else max(per_tier * 3, per_tier))
            for name, _, _ in TIER_BOUNDS
        }

    targets = _tier_targets()

    def _all_full() -> bool:
        return all(len(by_tier[name]) >= targets[name] for name, _, _ in TIER_BOUNDS)

    # Always probe GitHub: we need the default branch on every ProjectSpec,
    # and repos that return 404 can't be cloned so they're useless regardless
    # of the lockfile flag.
    gh_client = httpx.Client(timeout=15.0)
    prober = RepoProber(
        gh_client,
        check_lockfile=require_lockfile,
        cache_path=probe_cache,
    )
    try:
        for key in repo_order:
            if _all_full():
                break
            owner, repo = key
            rank_entries = by_repo[key]
            final_rank, npm_name, _meta = min(rank_entries, key=lambda t: t[0])
            tier = _tier_for(final_rank)
            if tier is None or len(by_tier[tier]) >= targets[tier]:
                continue
            try:
                info = prober.probe(owner, repo)
            except RepoProber.RateLimitExhausted as e:
                log.warning("aborting repo probe early: %s", e)
                break
            if info is None:
                continue
            if require_lockfile and not info.has_lockfile:
                continue
            by_tier[tier].append(ProjectSpec(
                npm_name=npm_name,
                rank=final_rank,
                tier=tier,
                git_url=f"https://github.com/{owner}/{repo}",
                github_owner=owner,
                github_repo=repo,
                default_branch=info.default_branch,
            ))
    finally:
        gh_client.close()

    selected: list[ProjectSpec] = []
    for tier, items in by_tier.items():
        items.sort(key=lambda s: s.rank)
        if tier == "top-100":
            selected.extend(items[:per_tier])
        else:
            if len(items) <= per_tier:
                selected.extend(items)
            else:
                selected.extend(rng.sample(items, per_tier))

    log.info("final sample: %d projects (%s)", len(selected),
             {t: len(i) for t, i in by_tier.items()})

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps([asdict(s) for s in selected], indent=2),
            encoding="utf-8",
        )
        log.info("wrote %s", output)

    return selected


def load_sample(path: Path) -> list[ProjectSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [ProjectSpec(**r) for r in raw]


def _tier_for(rank: int) -> str | None:
    for name, lo, hi in TIER_BOUNDS:
        if lo <= rank < hi:
            return name
    return None
