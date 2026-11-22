---
name: detection-engineering
description: Design, build, test, and tune detections (SIEM/EDR/Sigma) from a threat behavior to a deployed, low-false-positive rule — with ATT&CK mapping, validation against true and benign activity, and documentation.
version: 1.0.0
category: blue-team
tags: [detection-engineering, sigma, siem, mitre-attack, defensive]
authorization_required: false
destructive: false
mitre_attack: [T1059.001, T1047, T1053.005, T1218, T1021]
references:
  - https://attack.mitre.org/
  - https://github.com/SigmaHQ/sigma
  - https://car.mitre.org/
---

# Detection Engineering

## Purpose
Turn a threat behavior (from hunting, intel, or incidents) into a reliable,
maintainable detection that fires on malicious activity and stays quiet on benign
activity. Covers the full lifecycle: requirement → logic → validation → tuning →
deployment → documentation, with explicit false-positive handling.

## Prerequisites
- Access to detection platforms (SIEM, EDR) and their query languages, or Sigma
  for portable rule authoring.
- Representative log/telemetry and knowledge of available data sources & fields.
- A safe way to generate the target behavior for testing (lab, atomic tests) and
  a sample of benign activity for FP checks.
- MITRE ATT&CK familiarity.

## Scope & Authorization
- Authoring and testing use authorized telemetry and lab/atomic simulations.
- **Run attack simulations (e.g., Atomic Red Team) only in a lab or an
  authorized, controlled test window** — never unsanctioned on production.
- Follow change-management to deploy or modify production detections; avoid rules
  that could trigger automated disruptive responses without review.

## Methodology
1. **Requirement** — define the behavior to detect and its ATT&CK mapping; state
   the detection goal and expected data sources.
2. **Data validation** — confirm the needed telemetry exists, is parsed, and has
   the required fields and retention.
3. **Logic design** — write detection logic favoring robust behavioral signals
   over brittle static strings; consider evasion/variation.
4. **True-positive test** — generate the behavior safely (atomic test/lab) and
   confirm the rule fires.
5. **False-positive test** — run against historical/benign data; measure and
   reduce noise with context conditions and allow-lists.
6. **Tune & threshold** — balance fidelity vs coverage; add enrichment and
   severity.
7. **Document & deploy** — rule intent, data sources, FP guidance, response
   action; deploy via change control; schedule review.

## Execution Workflow
```
1. Requirement: "Detect encoded PowerShell execution (T1059.001)."
   - Expected data: process creation w/ command line (Sysmon EID 1 / 4688 / EDR).

2. Data check: confirm command-line logging is enabled and fields are parsed.

3. Draft logic (Sigma example — portable, convert to your SIEM):
```
```yaml
title: Suspicious Encoded PowerShell Command
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects PowerShell executed with an encoded command, a common
  obfuscation used by malware and offensive tooling.
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_flags:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
  condition: selection_img and selection_flags
falsepositives:
  - Legitimate administrative or software-deployment scripts using encoded commands
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```
```
4. TP test: run an atomic test in the lab that executes encoded PowerShell;
   confirm the rule fires with expected fields.

5. FP test: run the logic over 30+ days of benign data; review hits. Tune:
   - add parent-process / user / signing context
   - allow-list known admin tooling or deployment accounts
   - require additional suspicious indicators if noise is high.

6. Finalize: set severity, enrichment, and a response note. Convert Sigma ->
   platform rule. Deploy via change control. Set a review date.
```

## Validation
- **True positive:** the rule fires when the behavior is generated in a controlled
  test, with the expected entities/fields.
- **False positive rate:** measured against real benign data and reduced to an
  operationally acceptable level before deployment.
- **Resilience:** test obvious variations (different flags/casing/encodings) to
  avoid trivially bypassable logic.
- Peer review the rule and its FP guidance.

## Expected Output
- A deployed, documented detection: logic, ATT&CK mapping, data sources, severity,
  tested TP/FP results, FP handling, and response guidance.
- A portable Sigma rule where feasible, plus the platform-native version.
- Coverage note (what ATT&CK technique/variants this does and does not catch).

## False Positives
- Admin tooling and software deployment using the same primitives (encoded PS,
  WMI, scheduled tasks) — address with context, not deletion.
- Security/management agents generating matching telemetry.
- Over-fitting to one sample so real variants evade (false negatives) — balance.
- Parsing/field gaps causing missed or malformed matches — validate data first.

## Remediation
"Remediation" here = detection quality & coverage:
- Reduce FP rate with context conditions, enrichment, and maintained allow-lists.
- Close coverage gaps by mapping rules to ATT&CK and prioritizing blind spots.
- Version-control detections (detection-as-code), test in CI, and review on a
  cadence to prevent drift/decay.
- Document response actions so a firing rule leads to consistent triage.

## Reporting
```
Detection Rule Record
Title / ID / Status: <...>   ATT&CK: <techniques>
Intent: <what malicious behavior it detects>
Data sources: <...>   Fields required: <...>
Logic: <Sigma / platform query>
Validation: TP test result | FP rate over <window> | variants tested
False-positive guidance: <known benign causes + handling>
Severity / Response: <level; triage/response note>
Deployment: <platform, change ref, review date>
```

## References
- MITRE ATT&CK: https://attack.mitre.org/
- SigmaHQ (generic detection rules): https://github.com/SigmaHQ/sigma
- MITRE Cyber Analytics Repository (CAR): https://car.mitre.org/
