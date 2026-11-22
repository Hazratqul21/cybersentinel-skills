# Contributing to CyberSentinel Skills

Thanks for helping build a reliable, community-driven cybersecurity skill
ecosystem for AI agents. Please read this guide and [SECURITY.md](SECURITY.md)
before contributing.

## Ground rules

- **Authorized-use framing only.** Offensive skills must gate on authorization,
  default to non-destructive behavior, and include detection + remediation.
- **No fabrication.** No invented CVEs, tool capabilities, or unverified commands.
  Distinguish tested functionality from documentation-only examples.
- **No hardcoded personal paths, secrets, or real third-party targets.** Use
  placeholders (`example.com`, RFC 1918 ranges, `TARGET`).
- **No unnecessary dependencies.** Core tooling is stdlib-only.

## Adding a skill

1. Create `<category>/<subcategory>/<skill-name>/SKILL.md` using the template at
   [docs/skill-template/SKILL.md](docs/skill-template/SKILL.md).
2. The directory name is the canonical skill name — lowercase-hyphen, unique
   across the repo, matching the `name` frontmatter field.
3. Fill in **all 11 required sections** (Purpose, Prerequisites, Scope &
   Authorization, Methodology, Execution Workflow, Validation, Expected Output,
   False Positives, Remediation, Reporting, References).
4. Add framework mappings in frontmatter where applicable (`mitre_attack`,
   `owasp`, `cwe`, …) and link to **official/primary** references.
5. Optional: add `references/`, `scripts/`, `examples/`, `tests/`. Scripts must be
   non-destructive by default; justify any flagged pattern with a
   `# cybersentinel: allow-dangerous: <reason>` comment.

## Before you open a PR

```bash
make validate   # must pass with 0 errors
make test       # must pass
```

Run `cybersentinel validate --strict` to also treat warnings as errors.

## Pull request checklist

- [ ] `make validate` passes (0 errors)
- [ ] `make test` passes
- [ ] All required sections present and substantive (no placeholders)
- [ ] Offensive skill sets `authorization_required: true` and has Scope & Authorization
- [ ] Examples are lab-first and non-destructive
- [ ] References point to official sources; no invented CVEs/capabilities
- [ ] Detection and remediation guidance included for offensive techniques

## Style

- Clear, practical, professional prose. Prefer specificity over breadth.
- Keep commands copy-pasteable with placeholders; note required flags/intensity.
- Keep line length reasonable (~100 chars) in Markdown and code.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
