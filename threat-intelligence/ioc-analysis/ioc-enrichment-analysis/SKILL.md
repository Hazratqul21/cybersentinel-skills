---
name: ioc-enrichment-analysis
description: Triage, enrich, and assess indicators of compromise for an authorized investigation, validating each indicator, judging confidence and false-positive risk, pivoting to related infrastructure, and producing actionable, ATT&CK-mapped intelligence for detection and blocking.
version: 1.0.0
category: threat-intelligence
tags: [threat-intelligence, ioc, enrichment, pivoting, detection]
authorization_required: false
destructive: false
mitre_attack: [T1071, T1583]
references:
  - https://www.first.org/cvss/
  - https://attack.mitre.org/
  - https://www.misp-project.org/
---

# IOC Enrichment & Analysis

## Purpose
Turn raw indicators of compromise (hashes, IPs, domains, URLs, email artifacts)
into actionable intelligence: validate each one, enrich it with context, judge its
confidence and false-positive risk, pivot to related infrastructure, and map the
activity to ATT&CK. The deliverable is a vetted indicator set safe to feed into
detection and blocking without disrupting legitimate services.

## Prerequisites
- Authorization to investigate and to query enrichment sources for this case.
- The raw indicators and their origin (an alert, a report, an incident).
- Access to enrichment data (reputation/threat-intel sources, passive DNS, WHOIS,
  internal telemetry) consistent with their terms of use.
- A place to record indicators with confidence and provenance (e.g., a MISP-style
  structure).

## Scope & Authorization
- Confirm authorization and respect enrichment-source terms; do not exfiltrate
  sensitive case data to third-party services without approval.
- **Passive first.** Prefer passive enrichment (reputation, passive DNS, historical
  data) over active interaction that could tip off an adversary; get explicit
  approval before any active probing of attacker infrastructure.
- Protect sensitive indicators (internal hostnames, victim data) — share per the
  agreed handling/TLP level.
- Record provenance for every enrichment so conclusions are auditable.

## Methodology
1. **Normalize & dedupe** — standardize indicator formats; remove duplicates;
   defang for safe handling.
2. **Validate** — confirm each indicator is well-formed and plausibly malicious,
   not a common benign value (e.g., a shared CDN IP, a popular hash).
3. **Enrich** — add context: reputation, first/last seen, associated malware/
   campaigns, WHOIS/registration, passive DNS, geolocation, and internal sightings.
4. **Assess confidence** — judge how strongly each indicator ties to the threat and
   its false-positive risk.
5. **Pivot** — follow relationships (shared registrant, hosting, certificate,
   malware family) to discover related infrastructure (TA0042).
6. **Map** — associate indicators with ATT&CK techniques and, where known, an actor
   or campaign.
7. **Classify for action** — mark which indicators are safe to block/alert vs.
   monitor-only.

## Execution Workflow
> Defang indicators in notes. Prefer passive enrichment. Record the source of every
> enrichment and a confidence level per indicator.

```
1. Normalize/dedupe: canonicalize and defang (hxxp, [.]); drop duplicates.

2. Validate each indicator:
   - Filter known-benign/shared infrastructure (CDNs, popular files, sinkholes).

3. Enrich (passive):
   - Reputation, first/last seen, malware/campaign links, WHOIS, passive DNS,
     internal telemetry sightings.

4. Confidence:
   - Rate high/medium/low with the evidence and false-positive risk.

5. Pivot:
   - From a solid indicator, find related infra (same registrant/cert/host/family);
     repeat, tracking provenance.

6. Classify:
   - block/alert (high confidence, low FP) vs. monitor-only; map to ATT&CK.
```

## Validation
- Confirm each actioned indicator is genuinely malicious and low-FP; blocking a
  shared CDN or sinkhole causes outages — exclude those explicitly.
- Base confidence on corroborating evidence (multiple sources, internal sightings),
  not a single reputation hit.
- Verify pivots are real relationships, not coincidences (e.g., shared hosting on a
  large provider is weak; a unique self-signed cert reuse is strong).
- Keep provenance so every conclusion can be re-checked.

## Expected Output
- A vetted indicator set with type, value (defanged in docs), confidence,
  provenance, and ATT&CK mapping.
- A block/alert list vs. a monitor-only list, with exclusions for benign/shared
  infrastructure.
- Pivoted related infrastructure with the relationship evidence.
- A short narrative linking indicators to malware/campaign/actor where supported.

## False Positives
- Shared or benign infrastructure (CDNs, cloud ranges, popular legitimate files)
  flagged as malicious.
- Sinkholed domains/IPs (now defensive) treated as live attacker infrastructure.
- Weak pivots over large shared providers presented as confirmed links.
- Stale indicators that are no longer active — note first/last seen.

## Remediation
- Push high-confidence, low-FP indicators to EDR/SIEM/firewall for detection and
  blocking, with the exclusions applied.
- Create detections for the mapped techniques, not just the atomic indicators
  (which rotate quickly).
- Share vetted intelligence at the appropriate TLP with relevant teams/partners.
- Schedule re-validation so blocked indicators are retired as they go stale.

## Reporting
```
IOC Enrichment & Analysis
Case/Authorization: <id>   Source of indicators: <...>   TLP: <level>
Indicators: type | value (defanged) | confidence | provenance | ATT&CK ID | action
Enrichment summary: <reputation, first/last seen, malware/campaign links>
Pivots: <related infrastructure + relationship evidence>
Exclusions: <benign/shared/sinkholed indicators removed from blocking>
Recommendation: <block/alert list, detections for techniques, sharing>
```

## References
- FIRST (CVSS / threat-intel community): https://www.first.org/cvss/
- MITRE ATT&CK: https://attack.mitre.org/
- MISP Threat Intelligence Platform: https://www.misp-project.org/
