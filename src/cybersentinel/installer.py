"""Install skills into supported agent locations.

Each agent discovers skills from a different directory. We copy a skill's whole
directory into the agent's skills path. Existing files are never overwritten
unless ``force=True``.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# Per-agent default skill directories (relative to home unless absolute).
# These reflect each platform's actual loading mechanism; see docs/INTEGRATIONS.md.
AGENT_PATHS: Dict[str, str] = {
    "claude-code": "~/.claude/skills",
    "claude-desktop": "~/.claude/skills",
    "codex": "~/.codex/skills",
    "cursor": "~/.cursor/skills",
    "copilot": "~/.config/github-copilot/skills",
    "gemini-cli": "~/.gemini/skills",
    # Generic Agent Skills location.
    "agent-skills": "~/.agent-skills/skills",
}


@dataclass
class InstallResult:
    skill: str
    dest: Path
    status: str  # "installed", "skipped-exists", "overwritten"


def resolve_agent_dir(agent: str, custom_path: Optional[str] = None) -> Path:
    if custom_path:
        return Path(custom_path).expanduser().resolve()
    if agent not in AGENT_PATHS:
        raise ValueError(
            f"unknown agent '{agent}'. Known: {', '.join(sorted(AGENT_PATHS))}. "
            "Use --path to install to a custom location."
        )
    return Path(AGENT_PATHS[agent]).expanduser().resolve()


def install_skill(
    skill_dir: Path,
    dest_root: Path,
    force: bool = False,
    dry_run: bool = False,
) -> InstallResult:
    skill_dir = Path(skill_dir).resolve()
    dest = dest_root / skill_dir.name
    if dest.exists():
        if not force:
            return InstallResult(skill_dir.name, dest, "skipped-exists")
        if not dry_run:
            shutil.rmtree(dest)
            shutil.copytree(skill_dir, dest)
        return InstallResult(skill_dir.name, dest, "overwritten")
    if not dry_run:
        dest_root.mkdir(parents=True, exist_ok=True)
        shutil.copytree(skill_dir, dest)
    return InstallResult(skill_dir.name, dest, "installed")
