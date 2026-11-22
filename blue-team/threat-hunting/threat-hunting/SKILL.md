---
name: threat-hunting
description: Run hypothesis-driven threat hunts across endpoint, network, and cloud telemetry using MITRE ATT&CK, turning hunts into validated detections or confirmed incidents with documented evidence.
version: 1.0.0
category: blue-team
tags: [threat-hunting, detection, mitre-attack, defensive, analytics]
authorization_required: false
destructive: false
mitre_attack: [T1059, T1071, T1047, T1053, T1021]
references:
  - https://attack.mitre.org/
  - https://www.sans.org/white-papers/threat-hunting/
  - https://github.com/OTRF/ThreatHunter-Playbook
---

# Threat Hunting

## Purpose
Proactively search authorized environments for adversary activity that evaded
existing detections, using hypothesis-driven hunts grounded in MITRE ATT&CK. Each
hunt either confirms malicious activity (→ incident response), produces a new
validated detection, or documents a negative result with improved baselines.

## Prerequisites
- Read access to telemetry: EDR process/command-line, authentication, DNS/proxy,
  network flow, cloud audit logs, and a SIEM/analytics platform.
- Knowledge of the environment's baseline (normal admin tools, software, users).
- MITRE ATT&CK familiarity; a hypothesis backlog or threat-intel inputs.

## Prerequisites & Data Coverage
- Confirm which data sources and retention windows exist before scoping a hunt;
  gaps constrain what is huntable.

## Scope & Authorization
- Hunting uses authorized internal monitoring data within role and privacy policy.
- **Do not take disruptive actions** (isolate, disable, block) from a hunt — if a
  hunt confirms compromise, hand off to incident response via the approved
  process rather than reacting ad hoc.
- Handle any sensitive data surfaced (user content, credentials) per policy;
  preserve evidence rather than altering systems.

## Methodology
Hypothesis-driven loop:

1. **Hypothesis** — a specific, testable statement tied to ATT&CK, e.g.
   "an adversary is using WMI (T1047) for lateral movement."
2. **Scope & data** — which techniques/data sources; define the time window and
   the "normal" baseline to compare against.
3. **Analytic** — build a query/analytic that would surface the behavior; favor
   behavior over static IOCs for evasive threats.
4. **Investigate** — triage hits: enrich, establish context, separate benign from
   malicious using baselines and corroboration.
5. **Conclude** — confirmed malicious (→ IR), benign (document/baseline), or
   inconclusive (refine or note data gaps).
6. **Operationalize** — turn successful hunts into automated detections; record
   negative results and coverage.

## Execution Workflow
```
1. Pick a hypothesis from the backlog (intel-driven, crown-jewel-driven, or
   ATT&CK-coverage-driven). State the technique IDs and expected artifacts.

2. Define data + baseline:
   - data sources needed (e.g., EDR process events, 4688/Sysmon, network flow)
   - time window; what "normal" looks like for this behavior.

3. Build the analytic (pseudocode; adapt to your SIEM/EDR query language):
   - e.g., parent-child anomalies: office app spawning cmd/powershell/wscript
   - e.g., LOLBins with suspicious args (rundll32/regsvr32/mshta network use)
   - e.g., rare outbound beaconing: periodic connections, low jitter, long-lived
   - e.g., new service / scheduled task creation on servers

4. Investigate hits:
   - enrich (asset criticality, user role, process lineage, destination rep)
   - compare to baseline / known-good; look for corroborating signals
   - cluster by host/user/campaign.

5. Conclude and act:
   - malicious -> open an incident with the evidence package (-> incident-response)
   - benign    -> document; add to baseline/allow-list; tune noisy sources
   - unclear   -> refine analytic or record a data-coverage gap.

6. Operationalize: convert a good hunt into a detection rule (-> detection-
   engineering) and record coverage against the ATT&CK matrix.
```

## Validation
- A "hit" is malicious only with **corroborating evidence** across signals, not a
  single anomalous event; validate against the environment's baseline.
- Reproduce the analytic to confirm results are stable (not a query artifact).
- For confirmed activity, assemble a complete timeline before handing to IR.
- Record false-positive clusters so the eventual detection is tuned.

## Expected Output
- Hunt record: hypothesis, ATT&CK techniques, data sources, analytic used,
  findings, conclusion, and follow-up (detection created / baseline updated /
  gap noted).
- For confirmed threats: an IR handoff package (hosts, accounts, timeline, IOCs).
- An ATT&CK coverage/heat-map update reflecting what was hunted.

## False Positives
- Legitimate admin/IT tooling and automation mimicking attacker TTPs (PsExec,
  WMI, PowerShell remoting, scheduled tasks).
- Security/backup/management software generating unusual process or network
  behavior.
- Developer/CI activity on servers; software deployment and updates.
- Over-broad analytics — refine rather than repeatedly dismissing hits.

## Remediation
For a defensive skill, "remediation" = detection & posture improvement:
- Convert successful hunts into automated, tuned detections with documented FP
  handling (feed [`detection-engineering`](../../detection-engineering/)).
- Close telemetry/coverage gaps found during the hunt (missing log sources,
  short retention).
- Update baselines and allow-lists to reduce future noise.
- Feed confirmed TTPs/IOCs into blocking controls and intel.
- Track ATT&CK coverage to prioritize future hunts toward blind spots.

## Reporting
```
Threat Hunt Record
Hunt ID / Date / Hunter: <...>
Hypothesis: <statement>   ATT&CK: <technique ids>
Data sources: <...>   Window: <...>   Baseline: <what normal looks like>
Analytic: <query/logic summary>
Findings: <hits, enrichment, clustering>
Conclusion: <confirmed malicious | benign | inconclusive/data gap>
Follow-up: <detection created | baseline updated | coverage gap | IR opened>
Evidence: <queries, results, timeline>
```

## References
- MITRE ATT&CK: https://attack.mitre.org/
- SANS Threat Hunting resources: https://www.sans.org/white-papers/threat-hunting/
- ThreatHunter Playbook: https://github.com/OTRF/ThreatHunter-Playbook
