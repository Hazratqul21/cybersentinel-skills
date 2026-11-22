# Integrations

How to load CyberSentinel skills into supported AI agents. Loading mechanisms
differ per platform — verify against each tool's current documentation, since
these change over time. The common denominator is the Agent Skills format:
a `SKILL.md` with frontmatter in a skill directory.

Install with the CLI:

```bash
cybersentinel install --agent <agent>            # all skills
cybersentinel install --agent <agent> --skill sql-injection-testing
cybersentinel install --path /custom/location --category red-team
```

## Claude Code

Claude Code discovers skills from a `skills/` directory under its config
(user-level `~/.claude/skills/`, or a project-level `.claude/skills/`). Each skill
is a folder containing `SKILL.md`; Claude loads a skill's instructions when the
task matches its `description`.

```bash
cybersentinel install --agent claude-code
# or project-scoped:
cybersentinel install --path ./.claude/skills --category ai-security
```

Then invoke via natural language or, where supported, by the skill name.

## Claude Desktop

Claude Desktop uses the same `~/.claude/skills/` convention as Claude Code on the
same machine. Install once and both can see the skills.

```bash
cybersentinel install --agent claude-desktop
```

## OpenAI Codex

Place skill folders under Codex's skills directory (default `~/.codex/skills/` in
this tooling). Codex reads `SKILL.md` as structured guidance. Confirm the exact
path for your Codex version and override with `--path` if needed.

```bash
cybersentinel install --agent codex
```

## Cursor

Cursor can consume skills/rules from a project or user directory. This tooling
defaults to `~/.cursor/skills/`; many setups prefer a project-local path. Use
`--path` to target the location your Cursor configuration reads (e.g., a
`.cursor/` directory in your repo).

```bash
cybersentinel install --agent cursor
# or project-local:
cybersentinel install --path ./.cursor/skills --category blue-team
```

## GitHub Copilot

Copilot's custom instruction/skill mechanisms vary by surface (IDE vs CLI vs
coding agent). This tooling defaults to `~/.config/github-copilot/skills/`; adapt
with `--path` to whatever directory your Copilot configuration consumes. The
`SKILL.md` content is portable regardless of the exact loader.

```bash
cybersentinel install --agent copilot --path <copilot-skills-dir>
```

## Gemini CLI

Gemini CLI supports extensions/context directories. Default here is
`~/.gemini/skills/`; point `--path` at the directory your Gemini configuration
loads as context.

```bash
cybersentinel install --agent gemini-cli
```

## Generic Agent Skills runtimes

Any agent implementing the [Agent Skills](https://github.com/agentskills/agentskills)
convention can load these directly. Default location `~/.agent-skills/skills/`.

```bash
cybersentinel install --agent agent-skills
# or a fully custom location:
cybersentinel install --path /opt/agent/skills
```

## Manual installation

A skill is just a directory — copy it wherever your agent reads skills:

```bash
cp -r red-team/web-security/sql-injection-testing <your-agent-skills-dir>/
```

## Notes

- Install never overwrites existing files without `--force`.
- Use `--dry-run` to preview what would be installed.
- If a platform's path differs from the defaults above, use `--path`; the skill
  content is identical across platforms.
