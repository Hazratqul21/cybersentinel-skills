"""Discover CyberSentinel skills on disk."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .frontmatter import parse_frontmatter, FrontmatterError

TOP_LEVEL_CATEGORIES = [
    "red-team",
    "blue-team",
    "purple-team",
    "ai-security",
    "dfir",
    "threat-intelligence",
    "security-engineering",
    "shared",
]


@dataclass
class Skill:
    """An on-disk skill: a directory containing a SKILL.md."""

    path: Path
    name: str
    description: str = ""
    frontmatter: Dict[str, Any] = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None

    @property
    def category(self) -> str:
        return self.frontmatter.get("category", "")

    @property
    def tags(self) -> List[str]:
        t = self.frontmatter.get("tags") or []
        return [str(x) for x in t]

    @property
    def rel_id(self) -> str:
        """Repo-relative identifier, e.g. ``red-team/web-security/sql-injection-testing``."""
        try:
            return str(self.path.relative_to(repo_root()))
        except Exception:
            return self.name

    @classmethod
    def load(cls, skill_dir: Path) -> "Skill":
        skill_md = skill_dir / "SKILL.md"
        name = skill_dir.name
        try:
            text = skill_md.read_text(encoding="utf-8")
            fm, body = parse_frontmatter(text)
            return cls(
                path=skill_dir,
                name=str(fm.get("name", name)),
                description=str(fm.get("description", "")),
                frontmatter=fm,
                body=body,
            )
        except (OSError, FrontmatterError) as exc:
            return cls(path=skill_dir, name=name, error=str(exc))


def repo_root(start: Optional[Path] = None) -> Path:
    """Locate the repository root.

    Priority: ``CYBERSENTINEL_ROOT`` env var, then walk up from ``start`` (or
    this file) looking for a marker (``pyproject.toml`` or a top-level category
    directory), then fall back to two levels above this file.
    """
    env = os.environ.get("CYBERSENTINEL_ROOT")
    if env:
        return Path(env).resolve()

    here = (start or Path(__file__)).resolve()
    for parent in [here, *here.parents]:
        if (parent / "pyproject.toml").exists() and (parent / "red-team").is_dir():
            return parent
    # Fallback: src/cybersentinel/registry.py -> repo root is two up from src.
    return Path(__file__).resolve().parents[2]


def discover_skills(root: Optional[Path] = None) -> List[Skill]:
    """Return every skill (directory containing SKILL.md) under the category trees."""
    root = root or repo_root()
    skills: List[Skill] = []
    for category in TOP_LEVEL_CATEGORIES:
        base = root / category
        if not base.is_dir():
            continue
        for skill_md in sorted(base.rglob("SKILL.md")):
            skills.append(Skill.load(skill_md.parent))
    return skills
