---
name: api-security-testing
description: Assess authorized REST and GraphQL APIs against the OWASP API Security Top 10 — authorization flaws (BOLA/BFLA), broken authentication, excessive data exposure, mass assignment, and rate-limit gaps — with non-destructive proofs.
version: 1.0.0
category: red-team
tags: [api-security, web-security, authorization, owasp-api-top-10]
authorization_required: true
destructive: false
mitre_attack: [T1190, T1133]
owasp: [API1:2023, API2:2023, API3:2023, API5:2023, API6:2023]
cwe: [CWE-639, CWE-285, CWE-284]
references:
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
---

# API Security Testing

## Purpose
Evaluate an authorized API's security posture, focusing on the flaws that
dominate real-world API breaches: object- and function-level authorization
(BOLA/BFLA), broken authentication, excessive data exposure, mass assignment,
and missing rate limiting. Produce reproducible, non-destructive proofs and
clear remediation.

## Prerequisites
- Signed authorization and in-scope API base URLs/endpoints.
- API documentation / OpenAPI/Swagger / GraphQL schema if available.
- **At least two test accounts** (e.g., userA and userB) and, ideally, one
  privileged and one unprivileged role, to test authorization boundaries.
- Proxy (Burp/ZAP), `curl`, `jq`; for GraphQL, an introspection client.

## Scope & Authorization
- Require written authorization; confirm which methods are allowed and whether
  write operations (`POST`/`PUT`/`PATCH`/`DELETE`) may be exercised.
- **Non-destructive by default.** For BOLA/mass-assignment, prefer read proofs
  and reversible writes on your own test objects; never destroy or corrupt other
  users' data. Use accounts/objects you control to demonstrate cross-access.
- Obtain tokens/keys legitimately for the provided test accounts; never attempt
  to crack or reuse real users' credentials.
- Respect rate limits except where rate-limit testing is explicitly authorized.

## Methodology
1. **Enumerate** — endpoints, methods, parameters, object identifiers; for
   GraphQL, run introspection to map the schema.
2. **Authentication review** — token type (JWT/opaque/session), expiry,
   signature/alg, refresh flow, logout invalidation.
3. **BOLA (API1)** — as userA, access userB's object IDs; confirm the server
   enforces ownership, not just UI hiding.
4. **Broken auth (API2)** — weak/none JWT alg, missing expiry, token not bound
   to user, predictable identifiers.
5. **Excessive data exposure (API3)** — responses returning more fields than the
   client needs (PII, internal flags).
6. **BFLA (API5)** — can a low-priv role invoke admin functions by guessing
   method/route?
7. **Mass assignment (API6)** — inject extra fields (`role`, `isAdmin`,
   `verified`) into write requests on your own object and check acceptance.
8. **Rate limiting / resource (API4)** — are sensitive actions throttled?
   (test only if authorized)

## Execution Workflow
> `TOKEN_A`/`TOKEN_B` are tokens for two test accounts you control. Use your own
> object IDs to prove cross-access safely.

```bash
BASE="https://api.example.com"

# BOLA: userB's token reading userA's resource must be denied
curl -s -H "Authorization: Bearer $TOKEN_B" "$BASE/api/orders/1001" -o /dev/null -w "%{http_code}\n"
#   200 for another user's object with no ownership link => BOLA finding.

# Excessive data exposure: inspect returned fields
curl -s -H "Authorization: Bearer $TOKEN_A" "$BASE/api/users/me" | jq 'keys'
#   Look for PII/internal fields the client never uses.

# Mass assignment: add a privileged field to YOUR object
curl -s -X PATCH -H "Authorization: Bearer $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"displayName":"test","role":"admin"}' "$BASE/api/users/me" | jq .
#   If role changes to admin => mass assignment. (Revert afterwards.)

# BFLA: unprivileged token hitting an admin route
curl -s -H "Authorization: Bearer $TOKEN_A" "$BASE/api/admin/users" -o /dev/null -w "%{http_code}\n"

# JWT inspection (decode header/payload; do not forge against prod without scope)
echo "$TOKEN_A" | cut -d. -f1 | base64 -d 2>/dev/null | jq .   # check alg (e.g., none/HS256)
```

For GraphQL: run introspection, then test field-level authorization, nested
object access (BOLA via related objects), and query-depth/complexity limits.

## Validation
- An authorization finding requires a **concrete cross-account access**: userB
  retrieving/modifying userA's object, or a low-priv role invoking a high-priv
  function, reproducibly.
- For mass assignment, confirm the privileged field actually took effect
  server-side (re-read the object), then revert.
- Capture request, token identity (which account), response, and status.

## Expected Output
- Per finding: endpoint/method, OWASP API category, accounts/roles used, PoC
  request/response, demonstrated impact, severity (CVSS), remediation.
- An endpoint/authorization matrix (who can access what).
- Evidence bundle and a log of any writes made + reversions.

## False Positives
- A `200` that returns an **authorization error body** is not BOLA — inspect the
  payload, not just the status code.
- Field exposure that is actually required by the client is not "excessive."
- Mass-assignment fields that are silently ignored (not applied) — verify effect.
- Rate-limit "bypasses" caused by your own distributed source IPs/caching.

## Remediation
- Enforce **object-level authorization** on every request server-side (verify the
  authenticated principal owns/each may access the referenced object).
- Enforce **function-level authorization** by role on every sensitive route.
- Return only the fields the client needs (explicit response schemas/DTOs); never
  serialize whole ORM objects.
- Use allow-lists for writable fields to prevent mass assignment.
- Validate JWTs properly: reject `alg:none`, pin algorithms, verify signature,
  expiry, audience, and issuer; bind tokens to the subject.
- Apply rate limiting and resource quotas on sensitive and expensive operations;
  for GraphQL, enforce query depth/complexity limits and disable introspection
  in production.

## Reporting
```
Finding: <BOLA|BFLA|Broken Auth|Excessive Data|Mass Assignment> on <endpoint>
Authorization: <id>   OWASP: <APIx:2023>   Severity: <CVSS>
Accounts/roles used: <A/B, priv/unpriv>
PoC: <request as which identity> -> <response showing unauthorized effect>
Impact: <data/functions exposed>
Remediation: <server-side authz / schema / JWT fix> (see above)
Writes made & reverted: <yes/no, ref>
Evidence: <captures>
```

## References
- OWASP API Security Top 10 (2023):
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP REST Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
