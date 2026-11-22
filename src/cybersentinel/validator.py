"""Validate CyberSentinel skills against the specification.

Checks implemented:

- YAML frontmatter present and parseable
- required keys (name, description) present and well-formed
- name matches directory and the naming regex
- description length bounds
- recommended-key type/format checks (version semver, tags, booleans, mitre ids)
- required body H2 sections present
- offensive skills declare authorization and include a Scope & Authorization section
- duplicate skill-name detection (repo-wide)
- intra-repo relative link resolution (broken-link detection)
- dangerous-pattern scan of bundled scripts

The validator returns structured :class:`Issue` records with a severity so the
CLI can print a report and exit non-zero on errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .frontmatter import parse_frontmatter, FrontmatterError
from .registry import Skill, discover_skills, repo_root, TOP_LEVEL_CATEGORIES

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
MITRE_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MITRE_ATLAS_RE = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")

# Required H2 sections. Each entry is a list of acceptable heading keywords;
# a heading matches if it contains any keyword (case-insensitive).
REQUIRED_SECTIONS = [
    ("Purpose", ["purpose", "overview"]),
    ("Prerequisites", ["prerequisite", "requirements"]),
    ("Scope & Authorization", ["scope", "authorization", "authorisation"]),
    ("Methodology", ["methodology", "approach"]),
    ("Execution Workflow", ["execution", "workflow", "procedure"]),
    ("Validation", ["validation", "verify", "verification", "confirm"]),
    ("Expected Output", ["expected output", "output", "deliverable", "artifact"]),
    ("False Positives", ["false positive", "false-positive"]),
    ("Remediation", ["remediation", "mitigation", "hardening", "defen"]),
    ("Reporting", ["reporting", "report template", "report"]),
    ("References", ["reference", "further reading"]),
]

# Dangerous shell/code patterns that fail validation unless allow-listed.
DANGEROUS_PATTERNS = [
    (re.compile(r"rm\s+-rf\s+(/|/\s|\$HOME|~)(\s|$)"), "recursive delete of root/home"),
    (re.compile(r"\bmkfs\.")  , "filesystem format"),
    (re.compile(r"\bdd\b[^\n]*of=/dev/(sd|nvme|disk)"), "raw write to block device"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"), "curl/wget pipe to shell"),
    (re.compile(r">\s*/dev/(sd|nvme|disk)"), "redirect to block device"),
    (re.compile(r"\bchmod\s+-R\s+0?777\s+/"), "world-writable on root"),
    (re.compile(r"\bshutdown\b|\breboot\b|\bhalt\b"), "host power/state change"),
]
ALLOW_MARKER = "cybersentinel: allow-dangerous"

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"


@dataclass
class Issue:
    severity: str
    skill: str
    message: str
    location: str = ""

    def __str__(self) -> str:
        loc = f" ({self.location})" if self.location else ""
        return f"[{self.severity.upper()}] {self.skill}: {self.message}{loc}"


def _h2_headings(body: str) -> List[str]:
    out = []
    for line in body.splitlines():
        m = re.match(r"^\s{0,3}##\s+(.*\S)\s*$", line)
        if m and not line.lstrip().startswith("###"):
            out.append(m.group(1).strip().lower())
    return out


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_offensive(skill: Skill) -> bool:
    cat = (skill.frontmatter.get("category") or "").lower()
    if cat in {"red-team", "purple-team"}:
        return True
    rel = skill.rel_id.replace("\\", "/")
    if rel.startswith(("red-team/", "purple-team/")):
        return True
    tags = {str(t).lower() for t in skill.tags}
    if tags & {"offensive", "exploitation", "red-team"}:
        return True
    # AI red-teaming / jailbreak / prompt-injection are active techniques too.
    if any(k in rel for k in ("ai-red-teaming", "jailbreak", "prompt-injection", "attack-simulation")):
        return True
    return False


def validate_skill(skill: Skill) -> List[Issue]:
    issues: List[Issue] = []
    sid = skill.rel_id

    if skill.error:
        issues.append(Issue(SEVERITY_ERROR, sid, f"failed to load SKILL.md: {skill.error}"))
        return issues

    fm = skill.frontmatter

    # --- required keys ---
    name = fm.get("name")
    if not name:
        issues.append(Issue(SEVERITY_ERROR, sid, "missing required frontmatter key: name"))
    else:
        if not NAME_RE.match(str(name)):
            issues.append(Issue(SEVERITY_ERROR, sid, f"name '{name}' must match ^[a-z0-9]+(-[a-z0-9]+)*$"))
        if not (3 <= len(str(name)) <= 64):
            issues.append(Issue(SEVERITY_ERROR, sid, f"name '{name}' must be 3-64 chars"))
        if str(name) != skill.path.name:
            issues.append(
                Issue(SEVERITY_ERROR, sid, f"name '{name}' does not match directory '{skill.path.name}'")
            )

    desc = fm.get("description")
    if not desc:
        issues.append(Issue(SEVERITY_ERROR, sid, "missing required frontmatter key: description"))
    else:
        dlen = len(str(desc))
        if dlen < 20:
            issues.append(Issue(SEVERITY_ERROR, sid, f"description too short ({dlen} chars, min 20)"))
        if dlen > 500:
            issues.append(Issue(SEVERITY_ERROR, sid, f"description too long ({dlen} chars, max 500)"))
        if "\n" in str(desc):
            issues.append(Issue(SEVERITY_WARNING, sid, "description should be a single line"))

    # --- recommended keys ---
    version = fm.get("version")
    if version is not None and not SEMVER_RE.match(str(version)):
        issues.append(Issue(SEVERITY_WARNING, sid, f"version '{version}' is not valid semver"))

    category = fm.get("category")
    if category is not None and str(category) not in TOP_LEVEL_CATEGORIES:
        issues.append(Issue(SEVERITY_WARNING, sid, f"category '{category}' is not a known top-level category"))

    for key, regex, label in [
        ("mitre_attack", MITRE_ATTACK_RE, "ATT&CK technique id"),
        ("mitre_atlas", MITRE_ATLAS_RE, "ATLAS technique id"),
    ]:
        for item in _as_list(fm.get(key)):
            if not regex.match(str(item)):
                issues.append(Issue(SEVERITY_WARNING, sid, f"'{item}' is not a valid {label}"))

    for bkey in ("authorization_required", "destructive"):
        if bkey in fm and not isinstance(fm.get(bkey), bool):
            issues.append(Issue(SEVERITY_WARNING, sid, f"{bkey} should be a boolean"))

    # --- required body sections ---
    headings = _h2_headings(skill.body)
    for label, keywords in REQUIRED_SECTIONS:
        if not any(any(kw in h for kw in keywords) for h in headings):
            issues.append(Issue(SEVERITY_ERROR, sid, f"missing required section: '{label}'"))

    # --- safety: offensive skills must declare authorization ---
    if _is_offensive(skill):
        if fm.get("authorization_required") is not True:
            issues.append(
                Issue(SEVERITY_ERROR, sid, "offensive skill must set authorization_required: true")
            )
        if not any("authoriz" in h or "authoris" in h or "scope" in h for h in headings):
            issues.append(
                Issue(SEVERITY_ERROR, sid, "offensive skill must include a Scope & Authorization section")
            )

    # --- broken intra-repo links ---
    issues.extend(_check_links(skill))

    # --- dangerous script scan ---
    issues.extend(_scan_scripts(skill))

    return issues


_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _check_links(skill: Skill) -> List[Issue]:
    issues: List[Issue] = []
    sid = skill.rel_id
    for target in _LINK_RE.findall(skill.body):
        link = target.strip()
        if link.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path_part = link.split("#", 1)[0]
        if not path_part:
            continue
        resolved = (skill.path / path_part).resolve()
        if not resolved.exists():
            issues.append(Issue(SEVERITY_ERROR, sid, f"broken relative link: {link}", "SKILL.md"))
    return issues


def _scan_scripts(skill: Skill) -> List[Issue]:
    issues: List[Issue] = []
    sid = skill.rel_id
    scripts_dir = skill.path / "scripts"
    if not scripts_dir.is_dir():
        return issues
    for script in scripts_dir.rglob("*"):
        if not script.is_file():
            continue
        if script.suffix not in {".sh", ".bash", ".py", ".ps1", ".zsh", ""}:
            continue
        try:
            content = script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ALLOW_MARKER in content:
            continue
        for regex, label in DANGEROUS_PATTERNS:
            if regex.search(content):
                issues.append(
                    Issue(
                        SEVERITY_ERROR,
                        sid,
                        f"dangerous pattern in script ({label}); add '# {ALLOW_MARKER}: <reason>' to allow-list",
                        str(script.relative_to(skill.path)),
                    )
                )
    return issues


def validate_all(root: Optional[Path] = None) -> List[Issue]:
    root = root or repo_root()
    skills = discover_skills(root)
    issues: List[Issue] = []

    # Duplicate name detection.
    seen: Dict[str, str] = {}
    for sk in skills:
        nm = sk.name
        if nm in seen:
            issues.append(
                Issue(SEVERITY_ERROR, sk.rel_id, f"duplicate skill name '{nm}' (also at {seen[nm]})")
            )
        else:
            seen[nm] = sk.rel_id

    for sk in skills:
        issues.extend(validate_skill(sk))
    return issues


def summarize(issues: List[Issue]) -> Dict[str, int]:
    return {
        "errors": sum(1 for i in issues if i.severity == SEVERITY_ERROR),
        "warnings": sum(1 for i in issues if i.severity == SEVERITY_WARNING),
    }
