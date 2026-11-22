"""CyberSentinel Skills — a universal cybersecurity skill library for AI agents.

This package provides discovery, search, validation, and installation tooling
for Agent-Skills-compatible cybersecurity skills.
"""

__version__ = "0.1.0"

from .frontmatter import parse_frontmatter, FrontmatterError
from .registry import Skill, discover_skills, repo_root

__all__ = [
    "__version__",
    "parse_frontmatter",
    "FrontmatterError",
    "Skill",
    "discover_skills",
    "repo_root",
]
