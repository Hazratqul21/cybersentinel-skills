---
name: log-timeline-analysis
description: Correlate host and network logs from an authorized investigation into a unified, time-normalized timeline to reconstruct an intrusion end-to-end, confirm the activity window and scope, and produce an evidence-backed sequence of events mapped to MITRE ATT&CK.
version: 1.0.0
category: dfir
tags: [dfir, timeline-analysis, log-analysis, incident-response, correlation]
authorization_required: false
destructive: false
mitre_attack: [T1070, T1021, T1078]
references:
  - https://csrc.nist.gov/pubs/sp/800/61/r2/final
  - https://attack.mitre.org/
  - https://www.cisa.gov/resources-tools/resources/technical-approaches-detecting-and-remediating-malicious-activity
---

# Log & Timeline Analysis

## Purpose
Merge logs from many sources — endpoint, authentication, network, cloud, and
application — into a single time-normalized timeline so an intrusion can be
reconstructed end-to-end: initial access, the path through the environment, and
the full scope. Produce an evidence-backed sequence of events mapped to ATT&CK that
drives containment and the incident narrative.

## Prerequisites
- Authorization to access the relevant logs and investigate the incident.
- Access to the log sources (SIEM, EDR, auth/IdP, firewall/proxy/DNS, cloud audit)
  and knowledge of their formats and time zones.
- A working hypothesis or starting indicator (an alert, IOC, or suspicious event).
- A scratch workspace to assemble and query the combined timeline.

## Scope & Authorization
- Confirm you are authorized to access these logs; they may contain personal data —
  handle under policy and minimize retention of extracts.
- Preserve source logs: work on exports/copies and note their provenance and hashes
  where they are evidence.
- Normalize all timestamps to a single timezone (UTC) to avoid false sequencing.
- Account for **anti-forensics** (T1070): cleared or gapped logs are themselves a
  finding, not just missing data.

## Methodology
1. **Inventory sources** — list available logs, their coverage window, timezone,
   and retention; note gaps.
2. **Normalize** — convert timestamps to UTC and key fields to a common schema
   (time, host, user, source IP, action, result).
3. **Anchor** — start from the known indicator and expand outward in time.
4. **Correlate** — pivot across sources on shared keys (user, host, IP, process,
   session) to link events into a chain.
5. **Reconstruct** — order events into initial access → discovery → lateral
   movement → actions on objectives (TA0007/TA0008).
6. **Scope** — identify every affected account, host, and asset touched.
7. **Gap/tamper analysis** — flag missing intervals, cleared logs, and timezone
   inconsistencies.
8. **Map** — tag each confirmed step with an ATT&CK technique.

## Execution Workflow
> Normalize to UTC first. Keep a provenance note for every source. Distinguish
> "no activity" from "no logging".

```
1. Source inventory: list logs, coverage window, timezone, retention; mark gaps.

2. Normalize: parse to a common schema; convert all times to UTC.

3. Anchor + expand:
   - From the starting indicator, pull events ±window across sources.

4. Pivot/correlate:
   - Follow a user/host/IP/session across auth, endpoint, and network logs to build
     the chain (e.g., VPN login -> host logon -> remote exec -> outbound C2).

5. Scope:
   - Enumerate all accounts/hosts/assets in the chain; expand until the edges are
     clean (no further linked activity).

6. Tamper check:
   - Flag log-clearing events, coverage gaps, and timezone mismatches as findings.

7. Produce the ordered timeline; map steps to ATT&CK; list affected entities.
```

## Validation
- Confirm event ordering only after normalizing timezones; a sequencing claim on
  mixed timezones is unreliable.
- Corroborate each pivotal step across at least two independent sources where
  possible (e.g., auth log + endpoint log).
- Treat a log gap as "unknown," not "nothing happened"; verify whether logging was
  disabled or cleared.
- Preserve source references (log name, record id/time) for every timeline entry.

## Expected Output
- A unified, UTC-normalized timeline of the intrusion with per-event source
  references and ATT&CK mappings.
- A scope list: all affected accounts, hosts, and assets.
- A gaps/tampering section (missing intervals, cleared logs).
- IOCs and pivot values (IPs, accounts, hostnames) for further sweeping.

## False Positives
- Correlating unrelated events that merely share an IP (NAT/proxy) or a common
  service account — verify the link is causal.
- Apparent out-of-order events caused by clock skew or timezone errors.
- "Missing" activity that is actually outside a source's retention window, not
  evidence of tampering.

## Remediation
- Drive containment from the scope list (disable compromised accounts, isolate
  hosts) under the IR plan.
- Recommend logging improvements for the gaps found (coverage, retention, central
  forwarding, tamper-resistant storage).
- Feed pivot values/IOCs to detection so similar activity alerts in future.
- Preserve the timeline and source extracts for the case record.

## Reporting
```
Log & Timeline Analysis
Case/Authorization: <id>   Incident: <...>   Timezone: UTC
Sources: <logs, coverage window, gaps>
Timeline: UTC time | host/user | source | action | result | source ref | ATT&CK ID
Reconstruction: initial access -> ... -> actions on objectives
Scope: <affected accounts, hosts, assets>
Gaps/tampering: <missing intervals, cleared logs>
IOCs/pivots: <IPs, accounts, hostnames>
```

## References
- NIST SP 800-61r2 (Computer Security Incident Handling Guide):
  https://csrc.nist.gov/pubs/sp/800/61/r2/final
- MITRE ATT&CK: https://attack.mitre.org/
- CISA — Technical Approaches to Detecting and Remediating Malicious Activity:
  https://www.cisa.gov/resources-tools/resources/technical-approaches-detecting-and-remediating-malicious-activity
