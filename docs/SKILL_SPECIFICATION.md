# CyberSentinel Skill Specification (v1)

CyberSentinel skills follow the open [Agent Skills](https://github.com/agentskills/agentskills)
convention: a skill is a directory containing a `SKILL.md` file with YAML
frontmatter plus a Markdown body, optionally accompanied by `references/`,
`scripts/`, `examples/`, and `tests/` subdirectories.

This document is the authoritative contract that the CyberSentinel validator
(`cybersentinel validate`) enforces. It is intentionally vendor-neutral so the
same skill loads in Claude Code, Claude Desktop, OpenAI Codex, Cursor, GitHub
Copilot, Gemini CLI, and any other Agent-Skills-compatible runtime.

## 1. Directory layout

```
<category>/<skill-name>/
├── SKILL.md              # REQUIRED
├── references/           # optional: methodology.md, detection.md, remediation.md, ...
├── scripts/              # optional: helper scripts (non-destructive by default)
├── examples/             # optional: sample commands, redacted lab output
└── tests/                # optional: validation fixtures / unit tests
```

- The directory name is the canonical **skill name** and MUST match the
  `name` field in frontmatter.
- A skill lives exactly two levels below a top-level category
  (`red-team/`, `blue-team/`, …) OR three levels for sub-grouped categories
  (`ai-security/llm-security/<skill>/`). Both are accepted.

## 2. Naming convention

- Lowercase ASCII, words separated by single hyphens: `^[a-z0-9]+(-[a-z0-9]+)*$`.
- 3–64 characters.
- Must be unique across the entire repository (no duplicate skill names).
- Should be descriptive and action-oriented: `sql-injection-testing`,
  not `sqli` or `test1`.

## 3. Frontmatter (YAML)

Required keys:

| key          | type   | rule                                                             |
|--------------|--------|-----------------------------------------------------------------|
| `name`       | string | matches the directory name and the naming regex                 |
| `description`| string | 20–500 chars, single line, says *what* and *when to use*         |

Recommended keys (validated if present):

| key                     | type        | rule                                                      |
|-------------------------|-------------|-----------------------------------------------------------|
| `version`               | string      | semver `MAJOR.MINOR.PATCH`                                 |
| `category`              | string      | one of the top-level category slugs                       |
| `tags`                  | list[str]   | lowercase-hyphen tokens                                   |
| `authorization_required`| bool        | MUST be `true` for any offensive/active skill             |
| `destructive`           | bool        | `true` only if the skill can modify/impair a target       |
| `mitre_attack`          | list[str]   | technique IDs, e.g. `T1190`, `T1059.001`                  |
| `mitre_atlas`           | list[str]   | ATLAS technique IDs, e.g. `AML.T0051`                     |
| `owasp`                 | list[str]   | e.g. `A03:2021`, `API3:2023`, `LLM01:2025`                |
| `cwe`                   | list[str]   | e.g. `CWE-89`                                             |
| `references`            | list[str]   | URLs to primary/official sources                         |

Example:

```yaml
---
name: sql-injection-testing
description: Identify and safely validate SQL injection in authorized web targets, confirm exploitability without data destruction, and produce remediation guidance.
version: 1.0.0
category: red-team
tags: [web-security, injection, owasp-top-10]
authorization_required: true
destructive: false
mitre_attack: [T1190]
owasp: [A03:2021]
cwe: [CWE-89]
references:
  - https://owasp.org/www-community/attacks/SQL_Injection
  - https://cwe.mitre.org/data/definitions/89.html
---
```

## 4. Required body sections

Every `SKILL.md` body MUST contain these H2 sections, in any order. The
validator matches on the heading text (case-insensitive, leading emoji/words
allowed):

1. **Purpose** — what the skill does and the value it provides.
2. **Prerequisites** — tools, access, knowledge required.
3. **Scope & Authorization** — explicit authorization + scope-validation requirements.
4. **Methodology** — the technical approach, phased.
5. **Execution Workflow** — concrete, ordered steps the agent follows.
6. **Validation** — how to confirm a finding is real (proof-of-concept rules).
7. **Expected Output** — what artifacts/data the skill produces.
8. **False Positives** — common FPs and how to rule them out.
9. **Remediation** — defensive fixes and mitigations.
10. **Reporting** — a reusable reporting template.
11. **References** — links to official/primary sources.

## 5. Safety requirements

- Offensive or active skills MUST set `authorization_required: true` and include
  a **Scope & Authorization** section demanding written authorization and an
  in-scope target list before any action.
- Defaults MUST be non-destructive. Destructive or high-impact steps MUST be
  clearly marked and gated behind explicit operator confirmation.
- No skill may embed real credentials, live C2 infrastructure, working malware,
  or instructions whose primary purpose is unauthorized harm.
- Examples SHOULD be lab-first (use `example.com`, `10.0.0.0/8`, `TARGET`
  placeholders), never a real third party.
- Every offensive technique SHOULD pair with detection and remediation guidance.

## 6. Scripts

- Scripts are optional helpers; they MUST be non-destructive by default.
- Scripts are checked for syntax (`bash -n`, `python -m py_compile`) and scanned
  for dangerous patterns (see `scripts/security_scan` rules). Flagged patterns
  (`rm -rf /`, `mkfs`, `dd of=/dev/`, curl-pipe-to-shell, fork bombs, etc.)
  fail validation unless explicitly allow-listed with a justification comment.

## 7. Compatibility

Because the format is just `SKILL.md` + Markdown + optional plain files, skills
load anywhere the Agent Skills convention is supported. See
[`docs/INTEGRATIONS.md`](./INTEGRATIONS.md) for per-platform install paths —
verified per platform rather than assumed identical.
