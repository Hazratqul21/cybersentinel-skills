# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-23

First release. A vendor-neutral, Agent-Skills-compatible cybersecurity skill
library: **26 reference skills** across red team, blue team, purple team, AI/LLM
security, DFIR, and threat intelligence; a dependency-free Python validator and
CLI; **39 passing tests**; and GitHub Actions CI. All skills pass validation with
zero errors and zero warnings.

### Added — Phase 4 (CLI & CI finalization)
- End-to-end CLI tests (`tests/test_cli_commands.py`) driving `main()` for
  `list`/`search`/`info`/`validate`/`install`/`--version`, asserting exit codes
  and output. Test suite now **39 tests** (was 25).
- Verified the install flow end-to-end (dry-run writes nothing, real install
  copies `SKILL.md`, skip/`--force`/`--category` behave correctly).

### Added — Phase 3 (7 skills)
- Purple team: `adversary-emulation`, `detection-coverage-validation`.
- DFIR: `memory-forensics-analysis`, `disk-forensic-triage`,
  `log-timeline-analysis`.
- Threat intelligence: `ioc-enrichment-analysis`, `threat-actor-profiling`.
- Repository now ships **26 reference skills**, all passing validation.

### Added — Phase 2 (9 skills)
- Red team: `ssrf-testing`, `windows-privilege-escalation`, `aws-security-audit`.
- Blue team: `threat-hunting`, `detection-engineering`, `static-malware-analysis`.
- AI security: `llm-jailbreak-testing`, `rag-security-assessment`,
  `mcp-server-security-assessment`.
- Repository now ships **19 reference skills**, all passing validation.

### Added — Phase 1
- Repository architecture across all security domains (red/blue/purple, AI,
  DFIR, threat intelligence, security engineering, shared).
- Skill specification ([docs/SKILL_SPECIFICATION.md](docs/SKILL_SPECIFICATION.md))
  defining frontmatter and the 11 required body sections.
- Dependency-free Python validator and CLI (`cybersentinel`) with `list`,
  `search`, `info`, `validate`, and `install` commands.
- Validator checks: frontmatter parsing, naming, required sections, offensive
  authorization gating, duplicate detection, broken intra-repo links, and a
  dangerous-script scanner.
- 10 reference skills:
  - `web-reconnaissance`, `sql-injection-testing`, `xss-testing`,
    `api-security-testing`, `network-reconnaissance`, `active-directory-auditing`,
    `linux-security-auditing` (red team)
  - `soc-alert-triage`, `incident-response` (blue team)
  - `llm-prompt-injection-assessment` (AI security)
- Test suite (`tests/`) for the frontmatter parser and validator (19 tests).
- GitHub Actions CI running validation and tests.
- Project docs: README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, INTEGRATIONS.

[Unreleased]: https://github.com/Hazratqul21/cybersentinel-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Hazratqul21/cybersentinel-skills/releases/tag/v0.1.0
