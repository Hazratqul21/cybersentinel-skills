---
name: soc-alert-triage
description: Triage SOC/SIEM alerts consistently — enrich, validate true vs false positive, assess severity and scope, and decide escalate/close/monitor — producing a documented, repeatable decision with next actions.
version: 1.0.0
category: blue-team
tags: [soc-analysis, detection, triage, incident-response, defensive]
authorization_required: false
destructive: false
mitre_attack: [T1059, T1078, T1566, T1071]
references:
  - https://www.nist.gov/cyberframework
  - https://attack.mitre.org/
  - https://csrc.nist.gov/pubs/sp/800/61/r2/final
---

# SOC Alert Triage

## Purpose
Provide a consistent, defensible method for triaging security alerts from a
SIEM/EDR/IDS so analysts reach the same correct conclusion regardless of
experience: is this a true positive, how severe, what is the scope, and what
happens next. The output is a documented triage decision with evidence and
recommended actions.

## Prerequisites
- Read access to the SIEM/EDR and relevant log sources (auth, endpoint, network,
  cloud, email).
- Enrichment sources: asset inventory/CMDB, identity directory, threat-intel
  (reputation, IOC feeds), and the detection rule's logic/intent.
- Knowledge of MITRE ATT&CK and the organization's severity matrix and runbooks.

## Prerequisites & Access
- Analyst access is read-focused; containment actions follow the escalation path
  and change process.

## Scope & Authorization
- Triage uses authorized monitoring data within the analyst's role. Follow data-
  handling and privacy policy when viewing user/endpoint data.
- **Do not take disruptive containment actions** (isolate host, disable account,
  block) outside the approved runbook/authority level — escalate instead, unless
  pre-authorized playbooks delegate specific automated responses.
- Preserve evidence; avoid actions that tip off an active adversary before a
  response plan exists.

## Methodology
1. **Intake & context** — capture alert, rule intent, time, affected
   asset/identity, and detection confidence.
2. **Deduplicate & correlate** — group with related alerts; check for a broader
   campaign or known change/maintenance.
3. **Enrich** — asset criticality, user role, ge/ASN, process lineage, file
   hashes vs intel, destination reputation.
4. **Validate TP/FP** — compare observed behavior to the rule's intent and to a
   known-good baseline; look for corroborating evidence.
5. **Assess severity & scope** — impact × confidence × asset criticality;
   determine how many hosts/identities are involved.
6. **Decide** — close (FP/benign), monitor (low/uncertain), or escalate to
   incident response (TP with impact) — per the severity matrix.
7. **Document & act** — record rationale, map to ATT&CK, recommend/trigger next
   steps.

## Execution Workflow
```
1. Open alert -> record: rule name/intent, severity, entity (host/user), timestamp.
2. Pivot in SIEM around the entity +/- a time window:
   - authentication events (success/failure, source, MFA)
   - process/command-line (EDR) and parent-child lineage
   - network connections / DNS to the indicator
   - email/web context if phishing-related
3. Enrich indicators:
   - file hash -> intel/sandbox reputation
   - IP/domain -> reputation, ASN, first-seen, geo
   - account -> role, privilege, normal working hours/location
   - host -> criticality, owner, recent changes/patches
4. TP/FP decision: does evidence match malicious behavior the rule targets,
   or a benign explanation (admin tool, scanner, known job, software update)?
5. Severity: apply matrix (impact x confidence x asset value). Scope: count
   affected entities; check for lateral indicators.
6. Outcome:
   - FP/benign  -> close with reason; consider tuning the rule.
   - Uncertain  -> monitor / request more data; set a follow-up.
   - TP+impact  -> escalate to IR with a concise handoff package.
7. Write the triage note (template below) and update metrics.
```

## Validation
- A TP determination must rest on **corroborating evidence**, not a single
  signal (e.g., suspicious command line + outbound C2-like beacon + bad hash).
- Rule out benign causes explicitly (change ticket, known scanner, software
  behavior) before closing as FP.
- Confirm entity resolution (right host/user/time) to avoid mis-triage.
- Peer-review high-severity escalations where process requires.

## Expected Output
- A triage record per alert: verdict (TP/FP/benign/uncertain), severity, scope,
  ATT&CK mapping, evidence, decision rationale, and next action
  (close/monitor/escalate) with any tuning recommendation.
- For TPs: an IR handoff package (what, where, when, affected entities, IOCs).

## False Positives
- Admin/IT tooling (PsExec, PowerShell, remote management) mimicking attacker TTPs.
- Vulnerability scanners / security tools generating malicious-looking traffic.
- Expected software behavior, updates, or scheduled jobs.
- Geo/ASN "anomalies" from VPNs, travel, or cloud egress.
- Over-broad detection rules — recommend tuning rather than repeatedly closing.

## Remediation
This is a defensive skill; "remediation" here = detection & response improvement:
- Tune noisy rules (allow-list known-good, add context conditions) to cut FP rates.
- Close detection gaps revealed during triage (missing log sources, blind spots).
- Automate enrichment (intel, asset, identity lookups) to speed and standardize.
- Maintain runbooks per alert type; capture lessons to improve future triage.
- Feed confirmed IOCs/TTPs back into detections and blocklists.

## Reporting
```
Alert Triage Record
Alert: <rule name / id>   Detected: <timestamp>   Analyst: <...>
Entity: <host/user/ip>    Rule intent: <what it detects>
Verdict: <TP | FP | Benign | Uncertain>   Severity: <matrix>   Scope: <# entities>
ATT&CK: <technique ids>
Evidence: <correlated events, enrichment, process lineage, IOCs>
Rationale: <why this verdict>
Action: <close/monitor/escalate> | Tuning: <rule change recommended?>
IR handoff (if TP): <concise package>
```

## References
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- NIST SP 800-61 (Computer Security Incident Handling):
  https://csrc.nist.gov/pubs/sp/800/61/r2/final
- MITRE ATT&CK: https://attack.mitre.org/
