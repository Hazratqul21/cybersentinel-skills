---
name: web-reconnaissance
description: Map an authorized web target's attack surface — subdomains, hosts, technologies, endpoints, and exposed assets — using passive-first then light active techniques, producing a structured asset inventory.
version: 1.0.0
category: red-team
tags: [reconnaissance, osint, attack-surface, web-security]
authorization_required: true
destructive: false
mitre_attack: [T1595, T1595.002, T1592, T1590, T1596]
owasp: [A05:2021]
references:
  - https://owasp.org/www-project-web-security-testing-guide/
  - https://attack.mitre.org/techniques/T1595/
---

# Web Reconnaissance

## Purpose
Build a complete, accurate picture of an authorized web target's externally
reachable attack surface so later testing is focused and evidence-based. The
output is an asset inventory (hosts, subdomains, technologies, endpoints, open
services, and exposed artifacts) that feeds vulnerability testing skills and
the engagement report.

## Prerequisites
- Signed authorization and a defined scope (see below).
- Tooling (any subset): `whois`, `dig`/`nslookup`, `curl`, `httpx`, `subfinder`
  or `amass`, `nuclei`, `gowitness`/`eyewitness`, `whatweb`/`wappalyzer`.
  Passive sources: Certificate Transparency (crt.sh), search engines, Shodan/Censys.
- A scratch workspace and a note-taking/evidence system.
- Basic familiarity with DNS, HTTP, and TLS.

## Scope & Authorization
- **Do nothing before written authorization.** Obtain an engagement document
  that names the in-scope domains, IP ranges, and explicitly out-of-scope
  assets (shared hosting neighbors, third-party SaaS, CDNs you do not own).
- Validate every discovered asset against scope *before* touching it actively.
  Certificate Transparency and brute-forced subdomains frequently surface
  assets owned by other parties — treat those as out of scope.
- Respect rate limits and `robots.txt` intent for active phases; passive
  collection must not generate traffic to the target at all.
- Record the authorization reference (ticket/contract id) in the report.

## Methodology
Passive-first, then progressively more active:

1. **Seed definition** — confirm root domains, org names, ASN/IP ranges, known
   brands.
2. **Passive discovery** — WHOIS/RDAP, DNS records, Certificate Transparency,
   search-engine dorking, public code repos, Shodan/Censys. No packets to target.
3. **Subdomain enumeration** — aggregate passive sources, then optional DNS
   brute-force with a wordlist (light active).
4. **Resolution & liveness** — resolve names, probe for live HTTP(S) services.
5. **Fingerprinting** — identify web servers, frameworks, CMS, WAF/CDN, TLS
   config, and default/admin interfaces.
6. **Content discovery** — sitemaps, `robots.txt`, JS-referenced endpoints,
   common paths (gentle, scoped).
7. **Screenshot & triage** — capture live hosts, cluster by technology, flag
   high-interest assets (login, admin, staging, debug).

## Execution Workflow
> Replace `TARGET` / `example.com` with the authorized in-scope root. Examples
> use placeholders; confirm scope before running active steps.

```bash
# 1. Passive: WHOIS/RDAP and DNS records
whois example.com
dig +short example.com ANY
dig +short NS example.com; dig +short MX example.com; dig +short TXT example.com

# 2. Passive: Certificate Transparency (no traffic to target)
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | python3 -c "import sys,json;[print(r['name_value']) for r in json.load(sys.stdin)]" \
  | sort -u > subs_passive.txt

# 3. Subdomain enumeration (passive aggregation)
subfinder -silent -d example.com | sort -u >> subs_passive.txt
sort -u subs_passive.txt -o subs_passive.txt

# 4. Resolve + liveness (light active) — SCOPE-CHECK first
httpx -silent -l subs_passive.txt -status-code -title -tech-detect -o live_hosts.txt

# 5. Fingerprint technologies
whatweb -i live_hosts.txt --log-brief=whatweb.txt

# 6. Screenshots for triage
gowitness file -f live_hosts.txt --disable-db -P screenshots/

# 7. Safe, known-template checks (informational; no exploitation)
nuclei -l live_hosts.txt -severity info,low -tags exposure,tech -o nuclei_info.txt
```

## Validation
- De-duplicate and **scope-filter** the asset list; drop anything not covered by
  authorization.
- Confirm liveness with at least two signals (DNS resolution + HTTP response).
- Verify technology fingerprints against response headers / page content rather
  than trusting a single tool's guess.
- For any "sensitive" finding (exposed `.git`, admin panel, staging), confirm it
  is reachable and record the exact request/response as evidence — do **not**
  exploit it in this phase.

## Expected Output
- `assets.csv` / inventory: host, IP, port, service, technology, TLS summary,
  status code, title, screenshot path, scope status, notes.
- A deduplicated subdomain list and a live-hosts list.
- A shortlist of high-interest targets with rationale.
- Evidence bundle: raw tool outputs, screenshots, request/response captures.

## False Positives
- **Wildcard DNS** inflates subdomain brute-force results — detect by resolving
  a random non-existent subdomain; if it resolves, filter accordingly.
- **CDN/WAF IPs** (Cloudflare, Akamai, Fastly) are shared infrastructure, not
  the target's origin — do not attribute or attack.
- Stale Certificate Transparency entries may list decommissioned hosts; confirm
  liveness before reporting.
- Technology guesses from a single fingerprinter can be wrong; corroborate.

## Remediation
Defensive guidance to include for the asset owner:
- Minimize external attack surface; decommission stale subdomains and dangling
  DNS records (prevents subdomain takeover).
- Remove exposed development artifacts (`.git`, `.env`, backups, source maps).
- Restrict staging/admin interfaces to VPN/allow-listed networks.
- Review Certificate Transparency exposure and internal naming leakage.
- Deploy external attack-surface monitoring to catch new/forgotten assets.

## Reporting
```
Title: External Attack Surface — Web Reconnaissance
Authorization: <ticket/contract id>
Scope: <in-scope roots / ranges>   Date/Window: <...>
Summary: <N> roots, <N> subdomains, <N> live hosts, <N> high-interest assets.
Methodology: passive sources used; active steps and rate limits.
Inventory: (table) host | IP | port | service | tech | status | scope | notes
High-interest assets: asset, why it matters, evidence ref, recommended next step.
Risks observed: dangling DNS, exposed artifacts, staging exposure (with evidence).
Remediation: prioritized list (above).
Appendix: tool versions, raw outputs, screenshots.
```

## References
- OWASP Web Security Testing Guide — Information Gathering:
  https://owasp.org/www-project-web-security-testing-guide/
- MITRE ATT&CK T1595 (Active Scanning): https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1596 (Search Open Technical Databases):
  https://attack.mitre.org/techniques/T1596/
