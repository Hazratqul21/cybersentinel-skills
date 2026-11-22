---
name: sql-injection-testing
description: Identify and safely confirm SQL injection in authorized web applications and APIs — detect, prove exploitability non-destructively, assess impact, and provide remediation — without altering or destroying data.
version: 1.0.0
category: red-team
tags: [web-security, injection, owasp-top-10, database]
authorization_required: true
destructive: false
mitre_attack: [T1190]
owasp: [A03:2021]
cwe: [CWE-89]
references:
  - https://owasp.org/www-community/attacks/SQL_Injection
  - https://cwe.mitre.org/data/definitions/89.html
  - https://owasp.org/www-project-web-security-testing-guide/
---

# SQL Injection Testing

## Purpose
Find and confirm SQL injection (SQLi) vulnerabilities in an authorized target,
demonstrate exploitability with the least intrusive proof possible, assess the
blast radius, and hand developers precise remediation. The goal is evidence and
risk clarity, not data exfiltration or damage.

## Prerequisites
- Signed authorization and in-scope application/API list.
- An intercepting proxy (Burp Suite / ZAP), `curl`, and optionally `sqlmap`
  (used conservatively — see Scope).
- Understanding of SQL dialects (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) and
  of parameterized queries.
- A test/staging instance when available; coordinate on production.

## Scope & Authorization
- Require written authorization naming the target and acceptable intrusiveness.
- **Non-destructive by default.** Never run `UPDATE`/`DELETE`/`DROP`, never
  stack destructive statements, and avoid heavy time-based payloads that could
  degrade service. Prefer read-only proofs.
- If using `sqlmap`, cap it: `--level`/`--risk` low, `--technique` limited,
  `--flush-session` off, no `--os-shell`, no `--file-write`, and **no** data
  dumping beyond a single non-sensitive proof value unless explicitly authorized.
- Treat retrieved data as sensitive; capture the minimum needed to prove impact.
- Coordinate windows for any time-based testing on production.

## Methodology
1. **Map input vectors** — URL/query params, POST bodies, JSON fields, headers,
   cookies, path segments.
2. **Baseline** — record normal responses (status, length, timing, content).
3. **Detection** — probe with safe markers:
   - Error-based: `'`, `"`, `)`, `--` to provoke DB errors.
   - Boolean-based: compare `AND 1=1` vs `AND 1=2` style logic (parameterized
     to the context) for differential responses.
   - Time-based (blind): a *short*, bounded delay primitive to confirm execution.
   - UNION-based: column-count discovery via `ORDER BY` / `UNION SELECT NULL`.
4. **Confirmation** — reproduce a deterministic, non-destructive differential or
   controlled delay; identify DBMS and injection context (string/numeric/quoted).
5. **Impact assessment** — determine read scope (current DB/user, a harmless
   version string) without broad extraction.
6. **Remediation mapping** — tie each finding to the vulnerable parameter and
   code pattern.

## Execution Workflow
> Use placeholders. Confirm scope and intrusiveness before each active step.

```bash
# 0. Baseline (note length + timing)
curl -s -o /dev/null -w "%{http_code} %{size_download} %{time_total}\n" \
  "https://example.com/item?id=10"

# 1. Error-based probe
curl -s "https://example.com/item?id=10'"          # look for DB error / 500

# 2. Boolean-based differential (numeric context)
curl -s "https://example.com/item?id=10+AND+1=1"   # expect normal
curl -s "https://example.com/item?id=10+AND+1=2"   # expect different/empty

# 3. Time-based confirmation (bounded, short) — DBMS-specific, keep <= a few seconds
#    PostgreSQL example primitive: ... AND <short pg_sleep proof> (one request)

# 4. Optional automated confirmation, tightly constrained:
sqlmap -u "https://example.com/item?id=10" --batch \
  --level=1 --risk=1 --technique=BT --dbms=auto \
  --current-user --current-db        # minimal, read-only proof only
```

For non-GET inputs, drive the same logic through the proxy against the exact
request (JSON body, header, or cookie) rather than guessing.

## Validation
- A finding is confirmed only with a **reproducible** signal: a consistent
  boolean differential, a controlled time delay that tracks the injected value,
  a UNION-reflected marker, or a DB-specific error tied to your input.
- Re-test 2–3 times to rule out caching/jitter.
- Record the exact request, the response difference, DBMS, and context.
- Prove minimal impact (e.g., `current_user`/version) — stop there.

## Expected Output
- Per finding: endpoint, parameter, injection type and context, DBMS, PoC
  request/response, reproducibility notes, severity (CVSS), and data-at-risk
  description.
- A remediation note referencing the vulnerable code pattern.
- Evidence bundle (proxy history export, request/response captures).

## False Positives
- **WAF blocks / generic 500s** can mimic or mask SQLi — verify a *logic*
  differential, not just an error page.
- Response differences from caching, rate-limiting, or load balancers — retest
  and control timing.
- `sqlmap` "possible" results without a stable technique — manually reproduce
  before reporting.
- Time delays from network jitter — use multiple samples and vary the delay.

## Remediation
- Use **parameterized queries / prepared statements** (or a vetted ORM) for all
  data access; never build SQL by string concatenation.
- Apply strict input validation and type enforcement (e.g., numeric IDs).
- Enforce least-privilege DB accounts; separate read/write roles.
- Use allow-list logic for sort/column/table identifiers that cannot be bound.
- Add DB error handling that never leaks SQL errors to clients.
- Deploy a WAF as defense-in-depth (not a primary control) and log/alert on
  injection signatures.

## Reporting
```
Finding: SQL Injection in <endpoint> parameter <param>
Authorization: <id>   Severity: <CVSS vector/score>
Type/Context: <error|boolean|time|union> / <numeric|string|quoted>
DBMS: <...>
Proof (non-destructive): <request> -> <observed differential/delay>
Impact: <read scope demonstrated; potential if unaddressed>
Affected code pattern: <concatenated query / dynamic clause>
Remediation: parameterize; least-privilege; validation (see above)
Evidence: <proxy export / captures>
```

## References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP WSTG — Testing for SQL Injection:
  https://owasp.org/www-project-web-security-testing-guide/
