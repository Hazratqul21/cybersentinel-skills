"""CyberSentinel command-line interface.

Commands::

    cybersentinel list [--category C] [--json]
    cybersentinel search <query>
    cybersentinel info <skill-id>
    cybersentinel validate [--path DIR] [--strict]
    cybersentinel install --agent claude-code [--skill ID ...] [--category C]
                          [--path DIR] [--force] [--dry-run]

Implemented with argparse + stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .registry import Skill, discover_skills, repo_root
from .validator import validate_all, summarize, SEVERITY_ERROR, SEVERITY_WARNING
from .installer import install_skill, resolve_agent_dir, AGENT_PATHS


def _find_skill(skills: List[Skill], ident: str) -> Optional[Skill]:
    ident = ident.rstrip("/")
    for sk in skills:
        if sk.rel_id == ident or sk.name == ident:
            return sk
    # Allow suffix match on rel_id (e.g. "web-security/sql-injection-testing").
    for sk in skills:
        if sk.rel_id.endswith("/" + ident):
            return sk
    return None


def cmd_list(args) -> int:
    skills = discover_skills()
    if args.category:
        skills = [s for s in skills if s.rel_id.split("/")[0] == args.category]
    if args.json:
        print(json.dumps([
            {"id": s.rel_id, "name": s.name, "description": s.description, "tags": s.tags}
            for s in skills
        ], indent=2))
        return 0
    if not skills:
        print("No skills found.")
        return 0
    width = max((len(s.rel_id) for s in skills), default=0)
    for s in skills:
        desc = s.description or (s.error and f"<load error: {s.error}>") or ""
        print(f"{s.rel_id.ljust(width)}  {desc[:80]}")
    print(f"\n{len(skills)} skill(s).")
    return 0


def _norm(text: str) -> str:
    """Lowercase and strip non-alphanumerics so 'sqli' matches 'SQL injection'."""
    return "".join(ch for ch in text.lower() if ch.isalnum())


def cmd_search(args) -> int:
    q = args.query.lower().strip()
    qn = _norm(q)
    skills = discover_skills()
    hits = []
    for s in skills:
        hay = " ".join([s.rel_id, s.name, s.description, " ".join(s.tags), s.body]).lower()
        if q and q in hay:
            hits.append(s)
        elif qn and qn in _norm(hay):
            hits.append(s)
    for s in hits:
        print(f"{s.rel_id}\n    {s.description[:100]}")
    print(f"\n{len(hits)} match(es) for '{args.query}'.")
    return 0


def cmd_info(args) -> int:
    skills = discover_skills()
    sk = _find_skill(skills, args.skill)
    if not sk:
        print(f"Skill not found: {args.skill}", file=sys.stderr)
        return 2
    if sk.error:
        print(f"{sk.rel_id}\n  load error: {sk.error}", file=sys.stderr)
        return 2
    fm = sk.frontmatter
    print(f"ID:          {sk.rel_id}")
    print(f"Name:        {sk.name}")
    print(f"Description: {sk.description}")
    for key in ("version", "category", "authorization_required", "destructive"):
        if key in fm:
            print(f"{(key + ':').ljust(12)} {fm[key]}")
    if sk.tags:
        print(f"Tags:        {', '.join(sk.tags)}")
    for key, label in [("mitre_attack", "ATT&CK"), ("mitre_atlas", "ATLAS"),
                       ("owasp", "OWASP"), ("cwe", "CWE")]:
        val = fm.get(key)
        if val:
            print(f"{(label + ':').ljust(12)} {', '.join(str(x) for x in val)}")
    refs = fm.get("references") or []
    if refs:
        print("References:")
        for r in refs:
            print(f"  - {r}")
    bundles = [d for d in ("references", "scripts", "examples", "tests")
               if (sk.path / d).is_dir()]
    if bundles:
        print(f"Bundled:     {', '.join(bundles)}")
    return 0


def cmd_validate(args) -> int:
    root = Path(args.path).resolve() if args.path else repo_root()
    issues = validate_all(root)
    for issue in issues:
        print(issue)
    counts = summarize(issues)
    total_skills = len(discover_skills(root))
    print(f"\nValidated {total_skills} skill(s): "
          f"{counts['errors']} error(s), {counts['warnings']} warning(s).")
    if counts["errors"] > 0:
        return 1
    if args.strict and counts["warnings"] > 0:
        return 1
    return 0


def cmd_install(args) -> int:
    skills = discover_skills()
    selected: List[Skill] = []
    if args.skill:
        for ident in args.skill:
            sk = _find_skill(skills, ident)
            if not sk:
                print(f"Skill not found: {ident}", file=sys.stderr)
                return 2
            selected.append(sk)
    elif args.category:
        selected = [s for s in skills if s.rel_id.split("/")[0] == args.category]
    else:
        selected = skills

    try:
        dest_root = resolve_agent_dir(args.agent, args.path)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(f"Installing {len(selected)} skill(s) -> {dest_root}"
          + (" [dry-run]" if args.dry_run else ""))
    installed = skipped = overwritten = 0
    for sk in selected:
        if sk.error:
            print(f"  skip {sk.rel_id}: load error")
            continue
        res = install_skill(sk.path, dest_root, force=args.force, dry_run=args.dry_run)
        print(f"  {res.status:16} {sk.name}")
        if res.status == "installed":
            installed += 1
        elif res.status == "skipped-exists":
            skipped += 1
        elif res.status == "overwritten":
            overwritten += 1
    print(f"\nDone: {installed} installed, {overwritten} overwritten, {skipped} skipped."
          + ("" if not skipped else " (use --force to overwrite)"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cybersentinel",
                                description="Universal cybersecurity skill library for AI agents.")
    p.add_argument("--version", action="version", version=f"cybersentinel {__version__}")
    sub = p.add_subparsers(dest="command")

    pl = sub.add_parser("list", help="list available skills")
    pl.add_argument("--category")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_list)

    ps = sub.add_parser("search", help="search skills by keyword/tag")
    ps.add_argument("query")
    ps.set_defaults(func=cmd_search)

    pi = sub.add_parser("info", help="show details for a skill")
    pi.add_argument("skill")
    pi.set_defaults(func=cmd_info)

    pv = sub.add_parser("validate", help="validate skill structure")
    pv.add_argument("--path", help="repo/skill root to validate")
    pv.add_argument("--strict", action="store_true", help="treat warnings as errors")
    pv.set_defaults(func=cmd_validate)

    pin = sub.add_parser("install", help="install skills into an agent")
    pin.add_argument("--agent", default="claude-code",
                     help="target agent: " + ", ".join(sorted(AGENT_PATHS)))
    pin.add_argument("--skill", action="append", help="skill id (repeatable)")
    pin.add_argument("--category", help="install a whole category")
    pin.add_argument("--path", help="custom install directory")
    pin.add_argument("--force", action="store_true", help="overwrite existing files")
    pin.add_argument("--dry-run", action="store_true")
    pin.set_defaults(func=cmd_install)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
