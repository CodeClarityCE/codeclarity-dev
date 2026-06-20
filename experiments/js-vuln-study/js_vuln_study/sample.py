"""Top-N GitHub-stars sample of JS/TS projects with a committed lockfile.

We rank candidate repositories by GitHub stars (the standard popularity signal
for source projects) and keep those whose repository root commits BOTH a
`package.json` and a JS lockfile — a project without a lockfile resolves to zero
dependencies when scanned, and one without a `package.json` isn't a Node project.

The GitHub search API caps each query at 1000 results and sorts server-side, so
we pull the top few pages for `language:JavaScript` and `language:TypeScript`
(multiple `language:` qualifiers can't be OR-ed in one query), merge by stars,
then probe each repo's root contents in star order until `limit` repos qualify.
Probe results are cached by (owner, repo) so re-runs don't re-hit the API.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month"
SEARCH_LANGUAGES = ("JavaScript", "TypeScript")
SEARCH_PAGES = 3  # 100 results/page → up to 300 candidates per language
MIN_STARS = 1000  # floor for the search; the top-100 sits far above this
LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")
REQUIRED_FILE = "package.json"


@dataclass
class ProjectSpec:
    npm_name: str  # "owner/repo" — used as the CodeClarity project name + label
    rank: int  # 0-based star rank among the kept repos
    tier: str  # constant "top-100" (kept for downstream manifest/collect compatibility)
    git_url: str
    github_owner: str
    github_repo: str
    default_branch: str
    # npm registry cross-check (annotation; populated when the repo root's
    # package.json declares a name that resolves on the registry). Trailing
    # fields with defaults keep `load_sample` backward-compatible with older
    # sample.json files that predate them.
    npm_pkg: str | None = None  # real npm package name from root package.json
    npm_downloads: int | None = None  # last-month downloads, if published


def _auth_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _retry_get(
    http: httpx.Client,
    url: str,
    params: dict[str, Any] | None = None,
    max_wait: float = 120.0,
) -> httpx.Response | None:
    """GET with backoff that honours GitHub's primary/secondary rate limits."""
    headers = _auth_headers()
    for attempt in range(4):
        r = http.get(url, params=params, headers=headers)
        if r.status_code in (200, 404, 422):
            return r
        if r.status_code in (403, 429):
            retry_after = r.headers.get("Retry-After")
            remaining = r.headers.get("X-RateLimit-Remaining")
            reset = r.headers.get("X-RateLimit-Reset")
            if retry_after:
                wait = float(retry_after)
            elif remaining == "0" and reset:
                wait = max(1.0, float(reset) - time.time() + 2.0)
            else:
                wait = 2.0 * (2 ** attempt)
            if wait > max_wait:
                log.warning(
                    "github rate limit would require %.0fs (> cap %.0fs); giving up",
                    wait, max_wait,
                )
                return r
            log.warning("github %d; sleeping %.1fs", r.status_code, wait)
            time.sleep(wait)
            continue
        log.warning("unexpected github status %d for %s", r.status_code, url)
        return r
    return None


def _search_repos(http: httpx.Client, language: str, pages: int) -> list[dict[str, Any]]:
    """Return the top-starred repos for one `language:` query (server-side sorted)."""
    out: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        r = _retry_get(
            http,
            f"{GITHUB_API}/search/repositories",
            params={
                "q": f"stars:>{MIN_STARS} language:{language}",
                "sort": "stars",
                "order": "desc",
                "per_page": 100,
                "page": page,
            },
        )
        if r is None or r.status_code != 200:
            break
        items = r.json().get("items") or []
        if not items:
            break
        out.extend(items)
        # Search API is limited to ~30 req/min; a small pause keeps us clear.
        time.sleep(2.0)
    log.info("github search language=%s returned %d repos", language, len(out))
    return out


def _root_files(http: httpx.Client, owner: str, repo: str, branch: str) -> set[str] | None:
    """List root-level filenames for a repo, or None if the listing failed."""
    r = _retry_get(
        http,
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/",
        params={"ref": branch},
    )
    if r is None or r.status_code != 200:
        return None
    try:
        entries = r.json()
    except Exception:
        return None
    if not isinstance(entries, list):
        return None
    return {e.get("name") for e in entries if isinstance(e, dict)}


def _repo_metadata(http: httpx.Client, owner: str, repo: str) -> dict[str, Any] | None:
    """Return the authoritative repo object, or None if it doesn't resolve.

    `GET /repos/{owner}/{repo}` resolves renames/redirects (the client follows
    the 301 to the current slug), so the returned `full_name` is canonical. A
    404 (or any non-200) means the slug doesn't resolve.
    """
    r = _retry_get(http, f"{GITHUB_API}/repos/{owner}/{repo}")
    if r is None or r.status_code != 200:
        return None
    try:
        meta = r.json()
    except Exception:
        return None
    return meta if isinstance(meta, dict) else None


def _root_package_name(
    http: httpx.Client, owner: str, repo: str, branch: str
) -> str | None:
    """Return the `name` declared by the repo root's package.json, if any."""
    r = _retry_get(
        http,
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/package.json",
        params={"ref": branch},
    )
    if r is None or r.status_code != 200:
        return None
    try:
        payload = r.json()
        raw = base64.b64decode(payload["content"]) if payload.get("content") else b""
        name = json.loads(raw).get("name")
    except Exception:
        return None
    return name if isinstance(name, str) and name else None


def _npm_check(http: httpx.Client, name: str) -> tuple[bool, int | None]:
    """Return (published?, last-month downloads) for an npm package name.

    Plain registry gets (no GitHub auth header); any failure degrades to
    (False, None) so the npm cross-check never breaks sampling.
    """
    published = False
    downloads: int | None = None
    try:
        r = http.get(f"{NPM_REGISTRY}/{name}", headers={"Accept": "application/json"})
        published = r.status_code == 200
    except Exception:
        return False, None
    if not published:
        return False, None
    try:
        r = http.get(f"{NPM_DOWNLOADS_API}/{name}")
        if r.status_code == 200:
            value = r.json().get("downloads")
            if isinstance(value, int):
                downloads = value
    except Exception:
        downloads = None
    return published, downloads


class _ProbeCache:
    """Caches root-contents probe verdicts by (owner, repo) in a JSONL file."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}
        if path is not None and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._cache[(rec["owner"].lower(), rec["repo"].lower())] = rec
            log.info("loaded %d probe records from %s", len(self._cache), path)

    def get_or_probe(
        self, http: httpx.Client, owner: str, repo: str
    ) -> dict[str, Any]:
        """Resolve the canonical repo, probe its root, and cross-check npm.

        Keyed by the *search* slug so re-runs stay cached even though the verdict
        carries the canonical slug. A verdict that doesn't resolve (404/redirect
        to nothing) is recorded so we never re-probe a dead slug.
        """
        key = (owner.lower(), repo.lower())
        if key in self._cache:
            return self._cache[key]

        meta = _repo_metadata(http, owner, repo)
        if meta is None:
            rec = {
                "owner": owner,
                "repo": repo,
                "resolvable": False,
                "qualifies": False,
                "error": "unresolvable",
            }
            self._cache[key] = rec
            self._append(rec)
            return rec

        # Canonical, authoritative fields (override stale search-item values).
        c_full = meta.get("full_name") or f"{owner}/{repo}"
        c_owner = (meta.get("owner") or {}).get("login") or owner
        c_repo = meta.get("name") or repo
        c_branch = meta.get("default_branch")
        c_url = meta.get("html_url") or f"https://github.com/{c_owner}/{c_repo}"
        fork = bool(meta.get("fork"))
        archived = bool(meta.get("archived"))
        disabled = bool(meta.get("disabled"))

        names = _root_files(http, c_owner, c_repo, c_branch) if c_branch else None
        has_pkg = names is not None and REQUIRED_FILE in names
        has_lock = names is not None and any(lf in names for lf in LOCKFILES)

        npm_pkg: str | None = None
        npm_published = False
        npm_downloads: int | None = None
        if has_pkg and c_branch:
            npm_pkg = _root_package_name(http, c_owner, c_repo, c_branch)
            if npm_pkg:
                npm_published, npm_downloads = _npm_check(http, npm_pkg)

        rec = {
            "owner": owner,
            "repo": repo,
            "resolvable": True,
            "canonical_full_name": c_full,
            "canonical_owner": c_owner,
            "canonical_repo": c_repo,
            "canonical_branch": c_branch,
            "canonical_url": c_url,
            "fork": fork,
            "archived": archived,
            "disabled": disabled,
            "has_package_json": has_pkg,
            "has_lockfile": has_lock,
            "npm_pkg": npm_pkg if npm_published else None,
            "npm_published": npm_published,
            "npm_downloads": npm_downloads,
            "qualifies": (
                bool(c_branch)
                and not (fork or archived or disabled)
                and has_pkg
                and has_lock
            ),
        }
        self._cache[key] = rec
        self._append(rec)
        return rec

    def _append(self, rec: dict[str, Any]) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def build_sample(
    limit: int = 100,
    output: Path | None = None,
    probe_cache: Path | None = None,
    pages: int = SEARCH_PAGES,
    min_npm_downloads: int | None = None,
) -> list[ProjectSpec]:
    """Build a top-`limit` GitHub-stars sample of JS/TS repos that commit both a
    `package.json` and a lockfile, with canonical, resolvable slugs.

    Strategy: pull the top-starred repos for each language, merge and re-rank by
    stars, then for each repo in star order resolve its canonical slug via
    `GET /repos/{owner}/{repo}` (drops dead/redirecting URLs and forks), probe
    its root for a package.json + lockfile, and cross-check the npm registry —
    keeping those that qualify until `limit` are selected.

    `min_npm_downloads`, when set, additionally drops *published* packages whose
    last-month download count is below the threshold (low-signal libraries);
    repos not published to npm are kept regardless.
    """
    if not (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")):
        log.warning(
            "GITHUB_TOKEN not set — GitHub API is capped at 60/h unauthenticated; "
            "set a classic PAT with `public_repo` scope.",
        )

    # follow_redirects so a renamed repo's 301 from /repos/{owner}/{repo}
    # resolves to its canonical slug rather than surfacing as an error.
    http = httpx.Client(timeout=30.0, follow_redirects=True)
    cache = _ProbeCache(probe_cache)
    try:
        candidates: dict[tuple[str, str], dict[str, Any]] = {}
        for lang in SEARCH_LANGUAGES:
            for item in _search_repos(http, lang, pages):
                owner = (item.get("owner") or {}).get("login")
                name = item.get("name")
                if not owner or not name:
                    continue
                # Sample hygiene: drop forks, archived, and disabled repos so the
                # "top-N by stars" set is the canonical maintained projects rather
                # than high-star mirrors/forks (these fields ship on search items).
                if item.get("fork") or item.get("archived") or item.get("disabled"):
                    continue
                key = (owner.lower(), name.lower())
                stars = item.get("stargazers_count") or 0
                prev = candidates.get(key)
                if prev is None or stars > (prev.get("stargazers_count") or 0):
                    candidates[key] = item

        ranked = sorted(
            candidates.values(),
            key=lambda it: (-(it.get("stargazers_count") or 0), it["full_name"].lower()),
        )
        log.info("gathered %d unique candidate repos", len(ranked))

        selected: list[ProjectSpec] = []
        seen_canonical: set[str] = set()
        for item in ranked:
            if len(selected) >= limit:
                break
            owner = item["owner"]["login"]
            repo = item["name"]
            verdict = cache.get_or_probe(http, owner, repo)
            if not verdict.get("qualifies"):
                continue
            # Re-dedup on the canonical slug: a redirecting slug (react/react ->
            # facebook/react) collapses onto the canonical entry rather than
            # adding a duplicate.
            canonical = verdict["canonical_full_name"]
            if canonical.lower() in seen_canonical:
                continue
            # Opt-in low-signal filter: drop published packages below the
            # download floor; unpublished apps/monorepos are kept.
            downloads = verdict.get("npm_downloads")
            if (
                min_npm_downloads is not None
                and verdict.get("npm_published")
                and downloads is not None
                and downloads < min_npm_downloads
            ):
                log.info(
                    "dropped low-signal %s (npm %s, %d downloads < %d)",
                    canonical, verdict.get("npm_pkg"), downloads, min_npm_downloads,
                )
                continue
            seen_canonical.add(canonical.lower())
            rank = len(selected)
            selected.append(ProjectSpec(
                npm_name=canonical,
                rank=rank,
                tier="top-100",
                git_url=verdict["canonical_url"],
                github_owner=verdict["canonical_owner"],
                github_repo=verdict["canonical_repo"],
                default_branch=verdict["canonical_branch"],
                npm_pkg=verdict.get("npm_pkg"),
                npm_downloads=downloads,
            ))
            log.info(
                "kept #%d %s (%d stars)",
                rank, canonical, item.get("stargazers_count") or 0,
            )

        log.info("final sample: %d projects", len(selected))
        if len(selected) < limit:
            log.warning(
                "only %d/%d repos qualified; raise --pages to probe more candidates",
                len(selected), limit,
            )

        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps([asdict(s) for s in selected], indent=2),
                encoding="utf-8",
            )
            log.info("wrote %s", output)

        return selected
    finally:
        http.close()


def load_sample(path: Path) -> list[ProjectSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [ProjectSpec(**r) for r in raw]
