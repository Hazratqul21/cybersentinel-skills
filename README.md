# CyberSentinel Skills

**A universal, modular cybersecurity skill library for AI agents.**

CyberSentinel Skills is a structured, extensible collection of professional
cybersecurity skills that AI agents can load and execute **within authorized
environments**. It is not a chatbot — it is a vendor-neutral library of
Agent-Skills-compatible modules spanning Red Team, Blue Team, Purple Team, AI/LLM
Security, DFIR, Threat Intelligence, and Security Engineering.

Each skill follows the open [Agent Skills](https://github.com/agentskills/agentskills)
convention (`SKILL.md` + optional references/scripts/examples/tests), so the same
skill loads across Claude Code, Claude Desktop, OpenAI Codex, Cursor, GitHub
Copilot, Gemini CLI, and other compatible agents.

> ⚠️ **Authorized use only.** These skills are for authorized security testing,
> defensive operations, education, and controlled research. See
> [SECURITY.md](SECURITY.md) and each skill's *Scope & Authorization* section.

---

## Features

- **Broad coverage** across offensive, defensive, purple, and AI security domains.
- **Consistent skill format** — every skill has the same 11 required sections,
  from methodology to remediation to a reporting template.
- **Safety-first design** — explicit authorization requirements, non-destructive
  defaults, lab-first examples, and paired detection/remediation guidance.
- **Framework mappings** — MITRE ATT&CK / ATLAS / D3FEND, OWASP (Web/API/LLM),
  NIST CSF & SP 800-61 & AI RMF, CIS, CWE/CVE/CVSS/CAPEC.
- **Dependency-free validator & CLI** — discover, search, validate, and install
  skills with Python stdlib only (PyYAML optional).
- **CI-enforced quality** — frontmatter, naming, required sections, broken links,
  duplicate detection, and a dangerous-script scanner run in GitHub Actions.

## Architecture

```
cybersentinel-skills/
├── red-team/              reconnaissance, web, api, network, AD, linux, windows,
│                          cloud, wireless, mobile, exploit-dev, vuln-research, pentest
├── blue-team/             soc, threat-hunting, detection-eng, IR, endpoint,
│                          network-defense, cloud-defense, malware-analysis, hardening
├── purple-team/           attack-simulation, detection-validation, ATT&CK mapping
├── ai-security/           llm, prompt-injection, jailbreak, rag, mcp, agent, model, red-teaming
├── dfir/                  memory, disk, network, timeline, evidence-preservation
├── threat-intelligence/   osint, ioc-analysis, threat-actor, malware-intel
├── security-engineering/  secure-code-review, devsecops, container, k8s, supply-chain
├── shared/                methodologies, reporting, frameworks, references
├── src/cybersentinel/     Python CLI + validator (stdlib)
├── tests/                 validator & parser tests
├── docs/                  specification, integrations
└── .github/workflows/     CI
```

A skill lives at `<category>/<subcategory>/<skill-name>/SKILL.md`. See
[docs/SKILL_SPECIFICATION.md](docs/SKILL_SPECIFICATION.md) for the full contract.

## Supported AI agents

| Agent           | Skills directory (default)              |
|-----------------|-----------------------------------------|
| Claude Code     | `~/.claude/skills`                      |
| Claude Desktop  | `~/.claude/skills`                      |
| OpenAI Codex    | `~/.codex/skills`                       |
| Cursor          | `~/.cursor/skills`                      |
| GitHub Copilot  | `~/.config/github-copilot/skills`       |
| Gemini CLI      | `~/.gemini/skills`                      |
| Generic         | `~/.agent-skills/skills`                |

Loading mechanisms differ per platform; see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).
Paths can be overridden with `--path`.

## Installation

```bash
git clone https://github.com/innasoft/cybersentinel-skills.git
cd cybersentinel-skills

# Zero-dependency usage (stdlib only):
make list
make validate
make test

# Or install the CLI:
pip install -e .
cybersentinel --help
```

## Usage

```bash
cybersentinel list                                   # list all skills
cybersentinel list --category red-team               # filter by category
cybersentinel search sqli                             # fuzzy search
cybersentinel info web-security/sql-injection-testing # show skill details
cybersentinel validate                                # validate the whole repo
cybersentinel install --agent claude-code             # install all skills
cybersentinel install --agent codex --skill xss-testing --dry-run
cybersentinel install --path ./my-agent/skills --category blue-team
```

Install never overwrites existing files without `--force`.

## Skill directory (reference skills)

| Skill | Category | Purpose |
|-------|----------|---------|
| `web-reconnaissance` | red-team/reconnaissance | Map web attack surface |
| `sql-injection-testing` | red-team/web-security | Detect & confirm SQLi non-destructively |
| `xss-testing` | red-team/web-security | Reflected/stored/DOM XSS with benign proofs |
| `api-security-testing` | red-team/api-security | OWASP API Top 10 (BOLA/BFLA/mass-assign) |
| `network-reconnaissance` | red-team/network-security | Host/service discovery & inventory |
| `active-directory-auditing` | red-team/active-directory | AD misconfig & attack-path audit |
| `linux-security-auditing` | red-team/linux-security | Local privesc & hardening audit |
| `soc-alert-triage` | blue-team/soc-analysis | Consistent SIEM/EDR alert triage |
| `incident-response` | blue-team/incident-response | NIST SP 800-61 IR lifecycle |
| `llm-prompt-injection-assessment` | ai-security/prompt-injection | Direct/indirect prompt injection |
| `ssrf-testing` | red-team/web-security | SSRF incl. blind & cloud metadata |
| `windows-privilege-escalation` | red-team/windows-security | Local Windows privesc audit |
| `aws-security-audit` | red-team/cloud-security | CIS-aligned AWS misconfig audit |
| `threat-hunting` | blue-team/threat-hunting | Hypothesis-driven ATT&CK hunts |
| `detection-engineering` | blue-team/detection-engineering | Build & tune Sigma/SIEM detections |
| `static-malware-analysis` | blue-team/malware-analysis | Safe static triage & IOC extraction |
| `llm-jailbreak-testing` | ai-security/jailbreak-testing | Guardrail bypass-rate assessment |
| `rag-security-assessment` | ai-security/rag-security | RAG injection/poisoning/isolation |
| `mcp-server-security-assessment` | ai-security/mcp-security | MCP tool/agent security |
| `adversary-emulation` | purple-team/attack-simulation | Intel-driven actor emulation + detection scoring |
| `detection-coverage-validation` | purple-team/detection-validation | ATT&CK coverage via atomic tests |
| `memory-forensics-analysis` | dfir/memory-forensics | RAM analysis: injection, processes, IOCs |
| `disk-forensic-triage` | dfir/disk-forensics | Sound acquisition + artifact timeline |
| `log-timeline-analysis` | dfir/timeline-analysis | Unified UTC timeline from multi-source logs |
| `ioc-enrichment-analysis` | threat-intelligence/ioc-analysis | Validate, enrich & pivot indicators |
| `threat-actor-profiling` | threat-intelligence/threat-actor-analysis | Evidence-based actor TTP profile |

## Contribution guidelines

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: follow the skill spec, run
`make validate` and `make test`, keep examples lab-first and non-destructive, and
pair offensive techniques with detection + remediation.

## Security policy

See [SECURITY.md](SECURITY.md). Report vulnerabilities responsibly; use skills
only against assets you are authorized to test.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Roadmap

- Expand each category beyond the reference skills with full coverage.
- Add per-skill `references/` deep-dives (methodology/detection/remediation).
- Add framework cross-reference indexes in `shared/frameworks/`.
- Benchmarks and skill-quality scoring in `benchmarks/`.
- Signed releases and a hosted skill index.

See [CHANGELOG.md](CHANGELOG.md) for release history.
