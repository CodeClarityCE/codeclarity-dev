"""Study configuration: one `study.toml` per study directory, plus a 4-key
`.env` for secrets. Nothing else in the package reads `os.environ`: every
function takes a `Settings` (secrets) and/or a `Study` (parameters) instead.

A study directory holds a committed `study.toml` and `sample.json`; every
other artifact (manifest, raw blobs, tables, report) is generated and
gitignored (see the study's README for the full layout).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "study": {
        "name": None,  # defaults to the study directory's basename
        "sample": "sample.json",
        "frozen_from": None,  # optional: another study's manifest.jsonl, commit-pinned re-scan
        "snapshots": True,  # False = HEAD-only
        "knowledge_asof": None,  # optional YYYY-MM-DD vuln-finder cutoff for every analysis
        "retries": 2,
    },
    "grid": {
        # Inclusive date ranges, expanded by expand_grid(). The default
        # reproduces the study's canonical 40-date grid: 8 quarterly dates
        # (2022-2023) + 32 monthly dates (2024-01 through 2026-08).
        "quarterly": ["2022-01-01", "2023-10-01"],
        "monthly": ["2024-01-01", "2026-08-01"],
    },
    "codeclarity": {
        "org": None,  # defaults to "js-vuln-study-" + study name (one org per study)
        "analyzer": "js-vuln-study-v2",
        "plugins": {
            "js-sbom": "v0.0.25-alpha",
            "vuln-finder": "v0.0.25-alpha",
            "license-finder": "v0.0.18-alpha",
        },
        "clone_dir": None,  # default <repo-root>/private; "none" disables clean's clone sweep
    },
    "analyze": {
        "recency_cutoff": "2024-01-01",
        "triangulate": 0,  # HEAD subsample size for the osv-scanner cross-check; 0 skips it
    },
}


def _merge(defaults: dict, override: dict) -> dict:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in defaults.items()}
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _quarter_range(start: str, end: str) -> list[str]:
    y, m = int(start[:4]), int(start[5:7])
    ey, em = int(end[:4]), int(end[5:7])
    out = []
    while (y, m) <= (ey, em):
        out.append(f"{y:04d}-{m:02d}-01")
        m += 3
        if m > 12:
            m -= 12
            y += 1
    return out


def _month_range(start: str, end: str) -> list[str]:
    y, m = int(start[:4]), int(start[5:7])
    ey, em = int(end[:4]), int(end[5:7])
    out = []
    while (y, m) <= (ey, em):
        out.append(f"{y:04d}-{m:02d}-01")
        m += 1
        if m > 12:
            m = 1
            y += 1
    return out


def expand_grid(grid_cfg: dict) -> list[str]:
    """Two inclusive ranges (`quarterly`, `monthly`) -> a sorted date list."""
    dates: list[str] = []
    q = grid_cfg.get("quarterly")
    if q:
        dates += _quarter_range(q[0], q[1])
    mo = grid_cfg.get("monthly")
    if mo:
        dates += _month_range(mo[0], mo[1])
    return sorted(set(dates))


@dataclass
class Settings:
    """Secrets and connection info, read once from the environment."""

    cc_base_url: str
    cc_email: str
    cc_password: str
    github_token: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            cc_base_url=os.environ.get("CC_BASE_URL", "https://localhost/api"),
            cc_email=os.environ["CC_EMAIL"],
            cc_password=os.environ["CC_PASSWORD"],
            github_token=os.environ.get("GITHUB_TOKEN"),
        )


@dataclass
class Study:
    """One study directory's resolved configuration."""

    dir: Path
    name: str
    config: dict

    @classmethod
    def load(cls, study_dir: Path) -> "Study":
        study_dir = Path(study_dir)
        toml_path = study_dir / "study.toml"
        override: dict = {}
        if toml_path.exists():
            override = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        config = _merge(DEFAULTS, override)
        name = config["study"].get("name") or study_dir.name
        config["study"]["name"] = name
        if not config["codeclarity"].get("org"):
            config["codeclarity"]["org"] = f"js-vuln-study-{name}"
        return cls(dir=study_dir, name=name, config=config)

    @property
    def sample_path(self) -> Path:
        return self.dir / self.config["study"]["sample"]

    @property
    def frozen_from(self) -> Path | None:
        p = self.config["study"].get("frozen_from")
        return (self.dir / p).resolve() if p else None

    @property
    def snapshots(self) -> bool:
        return bool(self.config["study"]["snapshots"])

    @property
    def knowledge_asof(self) -> str | None:
        return self.config["study"].get("knowledge_asof")

    @property
    def retries(self) -> int:
        return int(self.config["study"]["retries"])

    @property
    def grid(self) -> list[str]:
        return expand_grid(self.config["grid"])

    @property
    def org_name(self) -> str:
        return self.config["codeclarity"]["org"]

    @property
    def analyzer_name(self) -> str:
        return self.config["codeclarity"]["analyzer"]

    @property
    def plugin_versions(self) -> dict:
        return self.config["codeclarity"]["plugins"]

    @property
    def clone_dir(self) -> Path | None:
        override = self.config["codeclarity"].get("clone_dir")
        if override == "none":
            return None
        if override:
            return Path(override).expanduser()
        repo_root = Path(__file__).resolve().parents[3]
        return repo_root / "private" if (repo_root / "backend").is_dir() else None

    @property
    def recency_cutoff(self) -> str:
        return self.config["analyze"]["recency_cutoff"]

    @property
    def triangulate_n(self) -> int:
        return int(self.config["analyze"]["triangulate"])

    @property
    def manifest_path(self) -> Path:
        return self.dir / "manifest.jsonl"

    @property
    def run_meta_path(self) -> Path:
        return self.dir / "run_meta.jsonl"

    @property
    def raw_dir(self) -> Path:
        return self.dir / "raw"

    @property
    def tables_dir(self) -> Path:
        return self.dir / "tables"

    @property
    def report_dir(self) -> Path:
        return self.dir / "report"

    @property
    def mining_cache_dir(self) -> Path:
        return self.dir / "mining_cache"
