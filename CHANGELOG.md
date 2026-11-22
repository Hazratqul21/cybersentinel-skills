# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/your-org/cybersentinel-skills/commits/main
