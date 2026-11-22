---
name: xss-testing
description: Detect and safely confirm reflected, stored, and DOM-based cross-site scripting in authorized web apps using benign proof payloads, assess impact, and provide context-aware remediation.
version: 1.0.0
category: red-team
tags: [web-security, xss, injection, owasp-top-10, client-side]
authorization_required: true
destructive: false
mitre_attack: [T1059.007, T1190]
owasp: [A03:2021]
cwe: [CWE-79]
references:
  - https://owasp.org/www-community/attacks/xss/
  - https://cwe.mitre.org/data/definitions/79.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
---

# XSS Testing

## Purpose
Identify and confirm cross-site scripting (reflected, stored, DOM-based) in an
authorized target, prove execution with a **benign** payload, determine context
and impact, and provide precise, context-aware remediation. Avoid any payload
that harms users, persists maliciously, or exfiltrates real data.

## Prerequisites
- Signed authorization and in-scope application list.
- Intercepting proxy (Burp/ZAP), a modern browser with devtools, `curl`.
- Understanding of HTML/JS contexts (HTML body, attribute, JS string, URL, CSS)
  and output-encoding rules.
- For stored XSS: a plan to clean up injected test artifacts.

## Scope & Authorization
- Require written authorization; confirm whether stored/persistent testing is
  allowed (it can affect other users and must be coordinated).
- **Benign proofs only.** Use non-destructive markers such as a unique string
  plus a visible, harmless `alert`/`console.log`/`print` of a nonce. Never
  deploy keyloggers, credential-stealers, worms, or beacons to third parties.
- Do not inject into fields visible to real users on production without explicit
  sign-off; prefer a test account and clean up afterwards.
- Treat any captured data as sensitive; capture only what proves execution.

## Methodology
1. **Enumerate sinks & sources** — every reflected input and every stored field;
   for DOM XSS, trace `location`, `document.*`, `postMessage` into sinks like
   `innerHTML`, `document.write`, `eval`, `setTimeout(string)`.
2. **Context identification** — determine where input lands (HTML text, tag
   attribute, quoted JS string, URL, event handler) — this dictates the payload.
3. **Reflected testing** — inject a unique nonce, observe reflection and
   encoding; escalate to a context-appropriate benign script proof.
4. **Stored testing** — submit a nonce payload, then verify execution on the
   render/view page(s); track every location it surfaces.
5. **DOM testing** — use devtools to follow source→sink data flow in client JS;
   confirm execution without server round-trip where applicable.
6. **Filter/encoding analysis** — note what is stripped/encoded to guide both
   confirmation and remediation.

## Execution Workflow
> Use a unique nonce like `cs<random>` so you can grep reflections. Keep proofs
> benign (visible alert/print of the nonce). Confirm scope for stored tests.

```bash
# 1. Reflected: does the input echo, and is it encoded?
NONCE="cs$RANDOM"
curl -s "https://example.com/search?q=${NONCE}<x>" | grep -n "$NONCE"
#    Inspect: is "<x>" encoded (&lt;x&gt;) or raw? Raw => investigate context.

# 2. Context-appropriate benign proof (example: HTML body context)
#    In a browser/proxy, submit:  <script>alert(document.domain)</script>
#    or an attribute-breakout proof for attribute context, etc.

# 3. Stored: submit nonce payload via the real request, then load the view page
#    and confirm the benign alert fires; note every page where it renders.

# 4. DOM-based: in devtools, set breakpoints on sinks (innerHTML, eval) and
#    trace a controlled location.hash/query value to the sink.
```

Use the browser (not just `curl`) to confirm **execution**, since reflection in
source is not proof of script execution.

## Validation
- Confirmed only when a **benign script actually executes** in the intended
  context (alert/console of the nonce, or observable DOM/JS effect), reproducibly.
- Distinguish reflection/encoding-bypass from execution.
- For stored XSS, confirm persistence and identify all affected views.
- Record request, exact payload, context, and a screenshot/console capture.

## Expected Output
- Per finding: URL/field, XSS type (reflected/stored/DOM), injection context,
  working benign PoC, affected pages/users, severity (CVSS), and encoding gaps.
- Cleanup log for any stored test artifacts.
- Evidence: screenshots/console output, proxy history, DOM trace notes.

## False Positives
- **Reflection without execution** — input echoed but correctly encoded is not
  XSS. Verify execution in a browser.
- **Self-XSS** that requires the victim to paste payload into their own console
  is generally low/again-not-a-vuln unless chained.
- WAF reflections or error pages echoing input harmlessly.
- Framework auto-escaping (React/Angular) often neutralizes payloads — confirm
  the actual rendered context.

## Remediation
- **Context-aware output encoding** at every sink (HTML, attribute, JS, URL, CSS)
  — use the framework's safe rendering, not manual string building.
- Prefer safe sinks (`textContent`) over dangerous ones (`innerHTML`, `eval`).
- Validate/normalize input, but treat output encoding as the primary control.
- Deploy a strong **Content-Security-Policy** (nonce/hash-based, no `unsafe-inline`)
  as defense-in-depth.
- Set `HttpOnly`/`Secure`/`SameSite` on session cookies to limit theft impact.
- For DOM XSS, use Trusted Types and avoid passing untrusted data to dangerous
  DOM APIs.

## Reporting
```
Finding: Cross-Site Scripting (<reflected|stored|DOM>) in <location>
Authorization: <id>   Severity: <CVSS>
Context: <HTML body|attribute|JS string|URL|event handler>
Benign PoC: <payload> -> <observed execution / screenshot ref>
Affected users/pages: <scope of impact>
Encoding gap: <what was not encoded>
Remediation: context-aware encoding; CSP; cookie flags (see above)
Cleanup: <stored artifacts removed? ref>
Evidence: <screenshots, proxy export>
```

## References
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP XSS Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
