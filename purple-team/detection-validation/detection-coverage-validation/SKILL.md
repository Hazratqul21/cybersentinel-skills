---
name: detection-coverage-validation
description: Validate a defensive program's detection coverage against MITRE ATT&CK by running controlled atomic tests, confirming the expected telemetry and alerts fire, and producing a prevented/detected/logged/blind coverage map with remediation for gaps.
version: 1.0.0
category: purple-team
tags: [purple-team, detection-validation, mitre-attack, atomic-testing, telemetry]
authorization_required: true
destructive: false
mitre_attack: [T1059, T1055, T1021]
references:
  - https://attack.mitre.org/
  - https://github.com/redcanaryco/atomic-red-team
  - https://center-for-threat-informed-defense.github.io/attack-flow/
---

# Detection Coverage Validation

## Purpose
Measure how well existing sensors and detections cover MITRE ATT&CK techniques by
running small, controlled "atomic" tests and confirming the expected telemetry and
alerts actually fire. The deliverable is an evidence-backed coverage map
(prevented / detected / logged-only / blind) and a prioritized plan to close gaps —
the detection-focused complement to full adversary emulation.

## Prerequisites
- Signed authorization and an in-scope test environment (or production with change
  control) with EDR/SIEM known to be forwarding.
- A target technique set (the org's ATT&CK priorities, or a layer from a threat
  model) and, per technique, the expected data source/telemetry.
- A controlled test method (e.g., Atomic Red Team definitions) and an operator host.
- Agreement with the SOC on deconfliction and a maintenance window.

## Scope & Authorization
- Written authorization required; atomic tests execute **real techniques** —
  restrict to scope, a defined window, and benign variants.
- **Non-destructive only.** Use benign test procedures and canaries; never run
  destructive, exfiltration, or persistence tests that are not cleaned up.
- Deconflict with the SOC (share the test schedule and action log) so simulated
  activity is distinguishable from real incidents.
- Use test hosts/accounts where possible; log every test with UTC timestamps.

## Methodology
1. **Select techniques** — prioritize by threat model and business impact; map each
   to an ATT&CK technique and its expected data components.
2. **Define tests** — for each technique, a benign, repeatable procedure and the
   precise telemetry/alert you expect (e.g., process creation, command line,
   registry key, network connection).
3. **Baseline sensors** — confirm the relevant sensors are healthy and forwarding
   before testing, so a gap is a detection gap, not an outage.
4. **Execute & observe** — run each test; query the SIEM/EDR for the expected
   telemetry and alert.
5. **Classify** — prevented / detected / logged-only / blind, with evidence and
   time-to-detect.
6. **Gap analysis** — for each blind/logged-only result, identify the missing data
   source or the detection rule to author.

## Execution Workflow
> Confirm sensor health first. Keep tests benign and logged; clean up every
> artifact a test creates.

```
1. Pre-check: verify EDR/SIEM ingestion is current for the target hosts (recent
   events present). Abort/flag if a sensor is down.

2. Per technique:
   - Run the benign atomic procedure; record host, user, command, UTC timestamp.
   - Search for expected telemetry (data component) and any alert.
   - Classify: prevented | detected | logged-not-alerted | blind.
   - Save evidence: event IDs/fields, alert link, raw command output.

3. Repeat variants (e.g., different execution methods for one technique) to avoid
   over-crediting a single brittle signature.

4. Clean up each test artifact immediately; confirm removal.

5. Aggregate results into an ATT&CK coverage layer.
```

## Validation
- A technique counts as **detected** only if an alert fired and is attributable to
  your test (verify via timestamp/host), not merely plausible.
- A technique counts as **logged-only** only if you can point to the raw telemetry
  event; otherwise it is **blind**.
- Re-run flaky results; report nondeterministic detections as a rate.
- Confirm sensor health for any "blind" result to rule out an outage.

## Expected Output
- An ATT&CK coverage map (e.g., a Navigator-style layer) scored per technique.
- Per technique: expected vs. observed telemetry, alert status, TTD, evidence.
- A prioritized gap list: missing data sources and detection rules to build.

## False Positives
- Crediting detection to a signature that actually matched unrelated noise — verify
  attribution.
- Scoring "blind" when the sensor was simply down or delayed — the pre-check guards
  this.
- Over-crediting one execution variant as full coverage of a technique — test
  multiple procedures.

## Remediation
- For each gap, onboard the missing data source or author/tune a detection mapped
  to the ATT&CK data component, then re-test to confirm closure.
- Reduce false positives on noisy rules in partnership with the SOC.
- Track coverage over time to catch detection drift after tooling or config
  changes.
- Prioritize remediation by the techniques most relevant to the org's threats.

## Reporting
```
Detection Coverage Validation
Authorization: <id>   Scope: <hosts/env>   Window: <start–end>
Sensor baseline: <EDR/SIEM health confirmed>
Coverage map: technique (ATT&CK ID) | expected telemetry | outcome
             (prevented/detected/logged/blind) | TTD | evidence
Gaps: <blind/logged-only techniques, prioritized>
Remediation: data sources to onboard, detections to build/tune
Deconfliction: <test schedule + action log shared with SOC>
Cleanup: <all test artifacts removed>
```

## References
- MITRE ATT&CK: https://attack.mitre.org/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- MITRE ATT&CK Flow / Center for Threat-Informed Defense:
  https://center-for-threat-informed-defense.github.io/attack-flow/
