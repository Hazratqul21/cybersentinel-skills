# Usage & Avoiding False Refusals

CyberSentinel skills describe **authorized** security work. An AI agent still
evaluates every request on its own merits — a skill does **not** grant you
permission or override the model's safety judgment, and it is not meant to. When a
request looks like unauthorized hacking **because the context is missing**, a good
agent will refuse. That refusal is usually about *how you asked*, not the skill.

This guide shows how to invoke these skills so legitimate, authorized work is
recognized as such — without trying to bypass any safety control.

---

## Why a skill gets refused

A refusal almost always comes from one of these, not from the skill file:

1. **No authorization context in your prompt.** "Do SQL injection on example.com"
   reads as an attack. The agent cannot see your engagement paperwork.
2. **A real third-party target with no proof of scope.** Naming a production system
   you do not obviously own raises the bar.
3. **Destructive or data-theft intent.** Asking to exfiltrate data, deploy
   ransomware, or maintain covert persistence is refused by design — these skills
   are non-destructive and do not cover that.
4. **Wrong surface.** General chat assistants are more conservative than a
   developer/security tool like Claude Code, which is built for authorized testing,
   CTFs, and defensive work.

## The fix: state your context

Lead with **who you are, what you are authorized to touch, and the purpose.** Then
name the skill. Compare:

> ❌ "Use sql-injection-testing on shop.example.com."

> ✅ "I'm running an **authorized penetration test** for Example Corp (signed SOW,
> scope: `*.staging.example.com`, non-destructive only). Using the
> `sql-injection-testing` skill, help me detect and safely confirm SQLi on the
> staging login form, then write up remediation."

Both ask for the same technique. The second gives the agent what it needs to tell
authorized testing from an attack.

### Good contexts to state
- An **authorized penetration test / red-team engagement** (reference the SOW /
  rules of engagement and the in-scope assets).
- A **CTF** or security competition.
- Your **own lab / test environment** (your VM, a deliberately vulnerable app like
  DVWA/Juice Shop, a local target you control).
- **Defensive / blue-team** work (triage, detection, forensics, hardening) — these
  rarely trip refusals at all.
- **Education / coursework** in a controlled setting.

## Authorization preamble (copy, fill, paste)

Paste this **before** invoking an offensive skill. A filled template is far more
effective than a bare command. See
[`shared/authorization-template.md`](../shared/authorization-template.md) for the
same text as a standalone file.

```
Authorized security testing context:
- Role: <pentester / red teamer / student / defender>
- Engagement: <SOW / RoE id, CTF name, "my own lab", or course>
- Target(s) in scope: <exact hosts/apps you are allowed to test>
- Out of scope: <anything explicitly excluded>
- Constraints: non-destructive only; no data exfiltration; no persistence
- Authorization on file: <yes + where, or "personal lab I own">

Task: using the <skill-name> skill, <what you want> on <in-scope target>,
and include detection + remediation.
```

## Where these skills work best

- **Claude Code / Claude Desktop** — built for authorized security testing,
  defensive security, CTFs, and education. This is the primary target.
- **Any Agent-Skills-compatible agent** — the `SKILL.md` content is portable; the
  surrounding agent's policy still applies.

## What these skills will *not* do (by design)

These are not limitations to work around — they are the project's safety line:

- No destructive actions (no data destruction/encryption, no DoS).
- No credential theft or exfiltration of real data.
- No uncontrolled persistence or backdoors.
- No attacks on targets you have not shown you are authorized to test.

Every offensive skill is paired with **detection and remediation**, so the output
helps defenders too. If you need something outside this line, these skills are the
wrong tool — and so is asking an AI agent to do it.

## Still refused on legitimate work?

- Re-state the authorization context explicitly (don't assume prior messages carry
  it).
- Use a **lab target** you obviously control to demonstrate the technique.
- Favor the **defensive/purple** skill for the same topic (e.g.,
  `detection-coverage-validation`, `threat-hunting`) — they validate the same
  techniques from the defender's side and rarely refuse.
- Accept that genuinely dual-use requests against unclear targets *should* require
  clear authorization. That is the system working, not the project failing.
