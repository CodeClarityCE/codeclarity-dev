"""Top-N GitHub-stars sample of JS/TS projects with a committed lockfile.

We rank candidate repositories by GitHub stars and keep those whose
repository root commits BOTH a `package.json` and a JS lockfile: a project
without a lockfile resolves to zero dependencies when scanned, and one
without a `package.json` isn't a Node project.

The GitHub search API caps each query at 1000 results and sorts server-side,
so we pull the top few pages for `language:JavaScript` and
`language:TypeScript` (multiple `language:` qualifiers can't be OR-ed in one
query), merge by stars, then probe each repo's root contents in star order
until `limit` repos qualify.

Only used to build a NEW corpus: the canonical `sample.json` for an existing
study is committed, and the sample-identity claim in RESULTS.md means it is
never regenerated for that study.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from . import github

log = logging.getLogger(__name__)

SEARCH_LANGUAGES = ("JavaScript", "TypeScript")
SEARCH_PAGES = 3  # 100 results/page -> up to 300 candidates per language
MIN_STARS = 1000
REQUIRED_FILE = "package.json"


@dataclass
class ProjectSpec:
    npm_name: str  # "owner/repo": the CodeClarity project name + manifest label
    rank: int  # 0-based star rank among the kept repos
    tier: str
    git_url: str
    github_owner: str
    github_repo: str
    default_branch: str


def _search_repos(http: httpx.Client, language: str, pages: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        r = github.get(
            http,
            "/search/repositories",
            params={
                "q": f"stars:>{MIN_STARS} language:{language}",
                "sort": "stars",
                "order": "desc",
                "per_page": 100,
                "page": page,
            },
        )
        if r.status_code != 200:
            break
        items = r.json().get("items") or []
        if not items:
            break
        out.extend(items)
        time.sleep(2.0)  # search API is limited to ~30 req/min
    log.info("github search language=%s returned %d repos", language, len(out))
    return out


def build_sample(
    limit: int, github_token: str | None, tier: str = "", output: Path | None = None
) -> list[ProjectSpec]:
    """Build a top-`limit` GitHub-stars sample of JS/TS repos with a root
    package.json + lockfile and a resolvable, canonical, non-fork slug.

    `tier` (the study name) is stamped on every spec before `output` is
    written, so the label reaches disk rather than only the returned objects."""
    if not github_token:
        log.warning(
            "GITHUB_TOKEN not set: GitHub API is capped at 60/h unauthenticated"
        )
    http = github.make_client(github.GITHUB_API, github_token, timeout=30.0)
    try:
        candidates: dict[tuple[str, str], dict[str, Any]] = {}
        for lang in SEARCH_LANGUAGES:
            for item in _search_repos(http, lang, SEARCH_PAGES):
                owner = (item.get("owner") or {}).get("login")
                name = item.get("name")
                if not owner or not name:
                    continue
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
            owner, repo = item["owner"]["login"], item["name"]
            meta = github.get_repo(http, owner, repo)
            if meta is None:
                continue
            canonical = meta.get("full_name") or f"{owner}/{repo}"
            if canonical.lower() in seen_canonical:
                continue
            if meta.get("fork") or meta.get("archived") or meta.get("disabled"):
                continue
            branch = meta.get("default_branch")
            if not branch:
                continue
            names = github.root_files(http, owner, repo, branch)
            has_pkg = names is not None and REQUIRED_FILE in names
            has_lock = names is not None and any(lf in names for lf in github.LOCKFILES)
            if not (has_pkg and has_lock):
                continue
            seen_canonical.add(canonical.lower())
            rank = len(selected)
            selected.append(ProjectSpec(
                npm_name=canonical,
                rank=rank,
                tier=tier,
                git_url=meta.get("html_url") or f"https://github.com/{owner}/{repo}",
                github_owner=(meta.get("owner") or {}).get("login") or owner,
                github_repo=meta.get("name") or repo,
                default_branch=branch,
            ))
            log.info("kept #%d %s (%d stars)", rank, canonical, item.get("stargazers_count") or 0)

        log.info("final sample: %d projects", len(selected))
        if len(selected) < limit:
            log.warning("only %d/%d repos qualified", len(selected), limit)

        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps([asdict(s) for s in selected], indent=2), encoding="utf-8"
            )
            log.info("wrote %s", output)
        return selected
    finally:
        http.close()


def load_sample(path: Path) -> list[ProjectSpec]:
    """Load a sample.json, tolerating extra keys from an older harness's
    format (npm_pkg/npm_downloads/etc. are silently dropped)."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    fields = {"npm_name", "rank", "tier", "git_url", "github_owner", "github_repo", "default_branch"}
    return [ProjectSpec(**{k: v for k, v in r.items() if k in fields}) for r in raw]
