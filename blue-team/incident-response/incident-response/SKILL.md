---
name: incident-response
description: Run a security incident through the NIST SP 800-61 lifecycle — preparation, detection and analysis, containment, eradication, recovery, and post-incident review — with evidence preservation and clear decision checkpoints.
version: 1.0.0
category: blue-team
tags: [incident-response, dfir, nist-800-61, defensive, containment]
authorization_required: false
destructive: false
mitre_attack: [T1486, T1078, T1021, T1059, T1567]
references:
  - https://csrc.nist.gov/pubs/sp/800/61/r2/final
  - https://www.nist.gov/cyberframework
  - https://attack.mitre.org/
---

# Incident Response

## Purpose
Guide responders through a security incident in a structured, evidence-preserving
way based on NIST SP 800-61, so containment and recovery are effective, decisions
are documented, and the organization learns from the event. Covers the full
lifecycle with explicit checkpoints and handoffs.

## Prerequisites
- An incident response plan, defined roles (IC, analysts, comms, legal), and
  contact tree.
- Access to logs/EDR/SIEM, affected systems (via approved process), and backups.
- Evidence-handling tooling and storage; a communications/ticketing channel.
- Knowledge of the environment's critical assets and recovery objectives (RTO/RPO).

## Scope & Authorization
- Containment, eradication, and recovery actions can disrupt production and
  destroy forensic evidence — perform them under the IR plan's authority and
  change process, with Incident Commander sign-off.
- **Preserve evidence before destructive remediation** (image/snapshot, capture
  volatile data) where legal/forensic needs require, unless safety demands
  immediate action.
- Engage legal/privacy/communications for breaches involving regulated data or
  disclosure obligations. Follow chain-of-custody for potential legal action.
- Do not "hack back" or take actions outside owned/authorized systems.

## Methodology
NIST SP 800-61 lifecycle:

1. **Preparation** — plan, tooling, baselines, and training in place beforehand.
2. **Detection & Analysis** — validate the incident, determine type, scope,
   entry point, and impact; build a timeline; classify severity.
3. **Containment** — short-term (stop the bleeding: isolate, block, disable) then
   long-term (sustainable controls while eradicating), balancing evidence
   preservation.
4. **Eradication** — remove the adversary's foothold: malware, persistence,
   compromised credentials, and exploited vulnerabilities.
5. **Recovery** — restore systems from trusted state, validate integrity, monitor
   closely for recurrence, return to normal operations.
6. **Post-Incident (Lessons Learned)** — retrospective, root cause, metrics, and
   improvements to controls and detections.

## Execution Workflow
```
DETECTION & ANALYSIS
  - Confirm it's a real incident (from triage/handoff). Assign IC and roles.
  - Classify: type (ransomware, BEC, intrusion, data theft...), severity, scope.
  - Scope it: affected hosts/accounts/data; entry vector; attacker actions.
  - Build a timeline (first activity -> detection -> now). Map to ATT&CK.
  - Start an incident log (every action, timestamped, who did it).

CONTAINMENT (with IC approval; preserve evidence first where required)
  - Short-term: isolate affected hosts (network quarantine), disable compromised
    accounts, block malicious IOCs, revoke tokens/sessions.
  - Preserve: memory/disk images, relevant logs, volatile data, before wiping.
  - Long-term: apply sustainable controls (segmentation, credential reset plan).

ERADICATION
  - Remove malware/persistence; close the exploited vulnerability; reset
    compromised credentials (coordinated, domain-wide if needed).
  - Verify the environment is clean before recovery (hunt for remaining footholds).

RECOVERY
  - Rebuild/restore from known-good backups or gold images; patch before reconnect.
  - Validate integrity and functionality; heighten monitoring for reinfection.
  - Phase systems back to production per business priority.

POST-INCIDENT
  - Within an agreed window, run a blameless retrospective: what happened, root
    cause, what worked, what to improve. Update plan, controls, detections.
```

## Validation
- Confirm scope is fully understood **before** declaring containment complete —
  incomplete scoping leads to re-compromise.
- Verify eradication by threat-hunting for residual persistence/credentials, not
  just removing the initial artifact.
- Validate recovered systems against a known-good baseline and monitor for
  recurrence before closing.
- Ensure the incident log and chain-of-custody are complete and consistent.

## Expected Output
- A maintained incident log/timeline with every action and decision.
- Scope assessment: affected assets, accounts, data; entry vector; attacker TTPs
  (ATT&CK-mapped).
- Containment/eradication/recovery action records and verification evidence.
- Preserved forensic evidence with chain-of-custody.
- Post-incident report with root cause and improvement actions.

## False Positives
- An "incident" that is actually authorized activity, maintenance, or a
  misconfiguration — re-validate before invoking disruptive response.
- Assuming a single compromised host when the adversary has spread — avoid
  premature "contained."
- Treating a symptom (one malware file) as the root cause.
- Benign anomalies from new tooling/telemetry.

## Remediation
Post-incident hardening (the "remediation" of IR):
- Close the exploited vulnerability and the control gaps that allowed spread
  (segmentation, least privilege, MFA, patching, backups/immutability).
- Improve detection for the observed TTPs; add/validate IOCs and behaviors.
- Update and exercise the IR plan; fix process gaps found in the retrospective.
- Address root cause, not just symptoms; track remediation items to closure.

## Reporting
```
Incident Report
Incident ID / Severity / Status: <...>   IC: <...>   Dates: detect -> close
Classification: <type>   ATT&CK: <techniques>
Executive summary: what happened, impact, current status.
Timeline: <key events, timestamped>
Scope: affected hosts/accounts/data; entry vector; attacker actions.
Response: containment / eradication / recovery actions + verification.
Evidence: preserved artifacts, chain-of-custody refs.
Root cause: <...>
Lessons learned & action items: <owner, due date>
```

## References
- NIST SP 800-61 Rev. 2: https://csrc.nist.gov/pubs/sp/800/61/r2/final
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- MITRE ATT&CK: https://attack.mitre.org/
