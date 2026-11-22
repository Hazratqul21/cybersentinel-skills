# Authorization Preamble Template

Copy this, fill it in, and paste it into your prompt **before** invoking an
offensive skill. Giving an AI agent explicit authorization context is the single
most effective way to have legitimate, authorized testing recognized as such. It
does not bypass any safety control — it supplies the context the agent needs to
tell authorized work from an attack.

See [`docs/USAGE.md`](../docs/USAGE.md) for the full explanation.

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

## Example (filled)

```
Authorized security testing context:
- Role: Penetration tester
- Engagement: SOW-2026-014, Example Corp external web assessment
- Target(s) in scope: *.staging.example.com
- Out of scope: production (*.example.com), any payment systems
- Constraints: non-destructive only; no data exfiltration; no persistence
- Authorization on file: yes, signed SOW held by Example Corp security team

Task: using the sql-injection-testing skill, help me detect and safely confirm
SQL injection on the staging login form, then write remediation guidance.
```

## For your own lab

```
Authorized security testing context:
- Role: Student / self-study
- Engagement: My own home lab
- Target(s) in scope: local DVWA at 127.0.0.1:8080 that I set up
- Out of scope: everything else
- Constraints: non-destructive only
- Authorization on file: personal lab I own

Task: using the xss-testing skill, walk me through confirming reflected XSS on my
local DVWA instance with a benign proof, and explain the fix.
```
