---
name: mcp-server-security-assessment
description: Assess an authorized Model Context Protocol (MCP) server and its agent integration for tool-poisoning, excessive tool permissions, prompt injection via tool results, authentication and secret handling, and unsafe tool actions, with remediation.
version: 1.0.0
category: ai-security
tags: [ai-security, mcp, ai-agent-security, tool-security, llm-security]
authorization_required: true
destructive: false
mitre_atlas: [AML.T0051, AML.T0053]
owasp: [LLM01:2025, LLM06:2025, LLM07:2025]
references:
  - https://modelcontextprotocol.io/
  - https://genai.owasp.org/llm-top-10/
  - https://atlas.mitre.org/
---

# MCP Server Security Assessment

## Purpose
Evaluate an authorized Model Context Protocol (MCP) server — and how an agent
consumes it — for the security risks of tool-using AI: malicious or poisoned tool
definitions, over-broad tool permissions, prompt injection delivered through tool
results, weak authentication/secret handling, and tools that can take unsafe
actions. Produce reproducible findings and remediation.

## Prerequisites
- Signed authorization and in-scope MCP server(s) and the agent/client integration.
- The server's tool manifest (names, descriptions, input schemas) and transport/
  auth configuration.
- A safe test environment, especially if tools perform real actions (filesystem,
  network, code execution, external APIs).
- Understanding of the MCP model: tools, resources, prompts, and how tool
  descriptions/results enter the model's context.

## Scope & Authorization
- Require written authorization; MCP tools can take **real actions** — test those
  only in a safe environment or with explicit, bounded approval.
- **Benign objectives only.** Demonstrate issues with harmless proofs (a canary, a
  dry-run, a read on a test resource) — do not destroy data, exfiltrate secrets,
  or trigger irreversible tool actions.
- Use test credentials/resources you control; never operate on real user data or
  production systems beyond read-only, in-scope checks.
- Coordinate with the server/integration owner.

## Methodology
1. **Enumerate** — tools, resources, prompts; their descriptions, input schemas,
   and declared side-effects; the transport (stdio/HTTP) and auth model.
2. **Tool-poisoning / description injection** — do tool *descriptions* or metadata
   contain hidden instructions that steer the agent (instructions in text the
   model reads as trusted)? (LLM01)
3. **Permission scope** — are tools over-powerful (arbitrary file/command/network
   access)? Is there least privilege and user confirmation for sensitive actions?
   (LLM07/LLM08-style excessive agency)
4. **Prompt injection via tool results** — can untrusted data returned by a tool
   (web content, file contents, API responses) inject instructions the agent then
   follows? (LLM01 indirect)
5. **Authentication & secrets** — is the server authenticated appropriately? Are
   API keys/tokens exposed in manifests, logs, errors, or results? (LLM06)
6. **Input validation & safety** — do tools validate inputs (path traversal,
   command injection, SSRF through a fetch tool)? Are destructive actions gated?
7. **Isolation** — can one tool/agent reach beyond its intended scope (filesystem
   roots, network egress, other tenants)?

## Execution Workflow
> Use a safe/test MCP deployment and canary tokens. Keep actions benign and
> reversible. Log everything.

```
1. Enumerate: list tools/resources/prompts; capture each tool's description and
   input schema. Flag descriptions containing imperative text aimed at the model
   ("always call X", "ignore...", hidden/encoded content).

2. Tool-poisoning check:
   - Review (or, in a lab, introduce) a tool whose description embeds instructions;
     run a normal agent task and see if the agent follows the embedded instruction
     (benign canary effect) -> tool-description injection.

3. Permission / excessive agency:
   - For each sensitive tool (file write, exec, network, email/send), check whether
     invocation requires user confirmation and is scoped. Attempt a benign out-of-
     scope action (e.g., read a path outside the intended root) in the lab.

4. Injection via tool results:
   - Have a tool return attacker-controlled-but-benign content containing an
     instruction + canary; see whether the agent executes it.

5. Auth & secrets:
   - Confirm the server requires auth as designed; grep manifests/logs/errors/
     results for exposed keys/tokens (use test secrets only).

6. Input validation:
   - Test a fetch/file tool for path traversal / SSRF / command injection using
     benign payloads in the lab; confirm validation.
```

## Validation
- Confirm each issue with a **reproducible, benign** demonstration: the agent
  following an injected instruction (canary), an out-of-scope action succeeding in
  the lab, or a secret appearing where it should not.
- Distinguish a real capability from the model merely *claiming* it — verify the
  tool call/action actually occurred.
- For nondeterministic agent behavior, report as a rate with sample size.
- Capture the tool definition/result, the agent's action, and the outcome.

## Expected Output
- Per finding: category (tool-poisoning / excessive agency / result-injection /
  auth-secret / input-validation / isolation), affected tool, benign PoC,
  reproducibility, OWASP LLM / ATLAS mapping, impact, remediation.
- A tool inventory with permissions and side-effects.
- Evidence: tool manifests, transcripts, lab action logs.

## False Positives
- Tool descriptions that are explanatory, not instructions to the model.
- An agent narrating an action it did not actually perform — verify the real call.
- "Secrets" that are placeholders/test values in examples.
- Out-of-scope access that is actually within the tool's intended (if broad) design
  — confirm intent with the owner.

## Remediation
- Treat **tool descriptions and tool results as untrusted**; the agent must not
  follow instructions embedded in them. Separate instructions from data; validate
  and sanitize tool outputs before they re-enter context.
- Apply **least privilege** to tools: narrow scopes (filesystem roots, allow-listed
  hosts), and require explicit **human confirmation** for sensitive/irreversible
  actions; allow-list action parameters.
- Authenticate the MCP server and clients; never embed secrets in manifests,
  descriptions, logs, errors, or results; use a secrets manager and scoped tokens.
- Validate all tool inputs (path traversal, command injection, SSRF) and sandbox
  tools that execute code or make network requests; restrict egress.
- Vet third-party MCP servers/tools before enabling (supply-chain risk); pin and
  review updates; log and monitor tool calls.

## Reporting
```
MCP Server Security Assessment
Authorization: <id>   Server / Integration: <...>
OWASP: <LLMxx:2025>   ATLAS: <AML.Txxxx>
Tool inventory: name | description | permissions/side-effects | auth
Findings: (per item) category | tool | benign PoC | reproducibility | impact |
          remediation
Auth & secrets: <server auth posture; any exposed secrets (test)>
Isolation / input validation: <results>
Remediation: untrusted tool I/O, least privilege + confirmation, secret handling
Evidence: <manifests, transcripts, lab logs>
```

## References
- Model Context Protocol: https://modelcontextprotocol.io/
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS: https://atlas.mitre.org/
