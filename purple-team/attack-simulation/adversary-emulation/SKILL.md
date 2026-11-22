---
name: adversary-emulation
description: Plan and execute an authorized, intelligence-driven adversary emulation that reproduces a specific threat actor's TTPs end-to-end to measure prevention, detection, and response, pairing each emulated technique with the expected telemetry and a detection outcome.
version: 1.0.0
category: purple-team
tags: [purple-team, adversary-emulation, attack-simulation, mitre-attack, detection]
authorization_required: true
destructive: false
mitre_attack: [T1059, T1055, T1021, T1003, T1071]
references:
  - https://attack.mitre.org/
  - https://github.com/center-for-threat-informed-defense/adversary_emulation_library
  - https://csrc.nist.gov/pubs/sp/800/115/final
---

# Adversary Emulation

## Purpose
Reproduce the tactics, techniques, and procedures (TTPs) of a chosen threat actor
in an authorized environment to measure, end-to-end, whether controls **prevent**,
whether sensors **detect**, and whether the SOC **responds**. Unlike a pure red
team, the goal is collaborative measurement: every technique is paired with the
telemetry it should produce and a pass/fail detection outcome, feeding concrete
detection and response improvements.

## Prerequisites
- Signed authorization, rules of engagement, scope, and emergency-stop contacts.
- A chosen actor/campaign and a cited TTP source (threat intel report, ATT&CK
  group page, or the ATT&CK Adversary Emulation Library).
- A pre-agreed emulation plan mapped to MITRE ATT&CK, reviewed by the blue team.
- A representative environment (production with change control, or a staging
  environment that mirrors it), plus logging/EDR known to be forwarding.
- Benign test artifacts (canary files, signed test tools) and cleanup procedures.

## Scope & Authorization
- Written authorization is mandatory; emulation exercises **real attack
  techniques** and must stay within the agreed scope and time window.
- **Non-destructive by default.** Use benign payloads and canaries; do not encrypt
  data, destroy systems, or exfiltrate real data — simulate impact with harmless
  markers and explicit, bounded approval for any higher-risk step.
- Coordinate with the blue team per the engagement model (announced/unannounced)
  and keep an emergency stop ready.
- Use test accounts/assets where possible; log every action with timestamps for
  deconfliction.

## Methodology
1. **Threat selection & intel** — pick an actor relevant to the org; extract their
   TTPs from cited reporting and map to ATT&CK techniques.
2. **Emulation plan** — order techniques across the kill chain (initial access →
   execution → persistence → priv-esc → defense evasion → cred access → discovery
   → lateral movement → collection → C2 → exfil/impact), each with a benign
   procedure and the **expected data source/telemetry**.
3. **Execution** — run each technique in sequence, capturing exact commands,
   timestamps, and host context for deconfliction.
4. **Detection measurement** — for each technique, record whether an alert fired,
   whether raw telemetry existed, and time-to-detect.
5. **Response measurement** — observe SOC triage/containment (announced exercises).
6. **Scoring** — classify each technique as prevented / detected / logged-only /
   blind, and map gaps to the data sources or detections that would close them.

## Execution Workflow
> Run from a controlled operator host. Keep payloads benign; log every command
> with a timestamp for blue-team deconfliction.

```
1. Load plan: ordered list of ATT&CK techniques with benign procedures + expected
   telemetry (e.g., T1059.001 PowerShell -> Script Block Logging / EDR process).

2. Per technique:
   - Execute the benign procedure; record host, user, command, UTC timestamp.
   - Query the SIEM/EDR for the expected telemetry and any alert.
   - Mark outcome: prevented | alerted | logged-not-alerted | no-telemetry.
   - Capture evidence (command output, event IDs, alert link).

3. Chain techniques to emulate realistic sequences (e.g., recon -> lateral
   movement) and check whether correlated/behavioral detections fire.

4. Deconflict: provide the blue team your action log so real vs. simulated
   activity is distinguishable.

5. Cleanup: remove canaries, persistence, and test artifacts; confirm restoration.
```

## Validation
- Confirm each executed technique actually ran (command output/host evidence) —
  do not score a technique you could not execute.
- Confirm each detection outcome against the SIEM/EDR, not assumption: an alert is
  "detected" only if it fired and was attributable to your action.
- Distinguish **prevented** (control blocked it), **detected** (alert fired),
  **logged-only** (telemetry exists, no alert), and **blind** (no telemetry).
- Record time-to-detect where measurable.

## Expected Output
- A coverage matrix: ATT&CK technique × outcome (prevented/detected/logged/blind)
  with evidence and time-to-detect.
- Per technique: the benign procedure, expected vs. observed telemetry, the gap,
  and a concrete detection/data-source recommendation.
- A deconfliction log (all actions, timestamps, hosts).

## False Positives
- An alert that fired from unrelated background activity, not your action — verify
  attribution via your timestamped log.
- "No detection" that is actually a forwarding/latency gap — confirm the sensor is
  healthy before scoring a technique blind.
- A technique scored as prevented that merely failed for environmental reasons
  (wrong path, missing dependency) rather than a control — re-test.

## Remediation
- For each blind/logged-only gap, specify the data source to onboard or the
  detection to build (map to ATT&CK data components), then re-test to confirm.
- Tune noisy or missed detections with the blue team; prioritize by the actor's
  most impactful techniques.
- Feed response gaps (slow triage, unclear ownership) into runbook and staffing
  improvements.
- Schedule periodic re-emulation to prevent detection drift; track coverage over
  time.

## Reporting
```
Adversary Emulation
Authorization: <id>   Actor/Campaign: <name>   Window: <start–end>
Intel source: <cited TTP source>
Coverage matrix: technique (ATT&CK ID) | procedure | expected telemetry |
                 outcome (prevented/detected/logged/blind) | TTD | evidence
Top gaps: <blind/logged-only techniques, ranked by impact>
Recommendations: data sources to onboard, detections to build, response fixes
Deconfliction log: <actions, timestamps, hosts>
Cleanup: <canaries/persistence removed, restoration confirmed>
```

## References
- MITRE ATT&CK: https://attack.mitre.org/
- Center for Threat-Informed Defense — Adversary Emulation Library:
  https://github.com/center-for-threat-informed-defense/adversary_emulation_library
- NIST SP 800-115 (Technical Guide to Information Security Testing):
  https://csrc.nist.gov/pubs/sp/800/115/final
