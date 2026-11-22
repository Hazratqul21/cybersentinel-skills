---
name: disk-forensic-triage
description: Perform forensically sound acquisition and triage of an authorized endpoint's disk to recover execution, persistence, file, and user-activity artifacts, preserving chain of custody and producing a timeline, findings, and IOCs mapped to MITRE ATT&CK.
version: 1.0.0
category: dfir
tags: [dfir, disk-forensics, incident-response, artifacts, timeline]
authorization_required: false
destructive: false
mitre_attack: [T1547, T1053, T1070, T1059]
references:
  - https://csrc.nist.gov/pubs/sp/800/86/final
  - https://www.sans.org/posters/windows-forensic-analysis/
  - https://attack.mitre.org/
---

# Disk Forensic Triage

## Purpose
Acquire and triage an endpoint's storage during an authorized investigation to
reconstruct what happened: program execution, persistence mechanisms, file
creation/deletion, anti-forensic activity, and user actions. Produce a defensible
timeline, findings, and IOCs mapped to ATT&CK, while preserving evidence integrity
and chain of custody.

## Prerequisites
- Authorization to investigate the system and an evidence-handling policy.
- A write-blocking acquisition method (hardware/software) and storage for the image.
- Knowledge of the OS and filesystem; the relevant artifact locations for that OS.
- A clean analysis workstation; never mount evidence read-write or analyze in place.

## Scope & Authorization
- Confirm authorization for this specific device; disks contain personal and
  sensitive data — handle under policy and minimize access.
- Follow the **order of volatility**: capture memory and other volatile data first
  where applicable, then image disk.
- Preserve **chain of custody**: image with a write blocker, hash at acquisition,
  document handling, and analyze only verified copies (mounted read-only).
- Do not alter the source media; record any unavoidable changes.

## Methodology
1. **Acquire** — create a forensic image with a write blocker; record tool, time,
   operator, and a cryptographic hash; verify the copy.
2. **Timeline** — build a filesystem and super-timeline (MACB times, logs,
   registry/journal) to anchor the investigation.
3. **Execution evidence** — recover program-execution artifacts (e.g., prefetch,
   shimcache/amcache, userassist, bash/shell history) (T1059).
4. **Persistence** — review autostart locations, scheduled tasks/cron, services,
   run keys, and startup items (T1547, T1053).
5. **File activity** — carve deleted files, inspect recycle/trash, and recover
   artifacts of staging or tooling.
6. **Anti-forensics** — detect log clearing, timestomping, and wiping (T1070).
7. **User activity** — browser history, recent files, shell/PowerShell logs, and
   account usage relevant to the hypothesis.
8. **IOCs** — extract hashes, paths, and indicators for estate-wide sweeping.

## Execution Workflow
> Mount the verified image read-only on an isolated workstation. Record every tool
> and command for reproducibility.

```
1. Acquire + verify:
   - Image source via write blocker; compute SHA-256; log acquisition metadata.
   - Verify image/copy hash; mount read-only. Work on the copy only.

2. Timeline:
   - Generate a filesystem timeline + super-timeline; identify the suspected
     activity window.

3. Execution artifacts:
   - Parse execution evidence (OS-appropriate) for unknown binaries and first/last
     run times.

4. Persistence:
   - Enumerate autostart/scheduled-task/service locations; flag unusual entries.

5. Files + anti-forensics:
   - Carve deleted items; check for log clearing, timestomping (MACB anomalies),
     and wiping.

6. User activity:
   - Review browser, recent-docs, shell history for the window.

7. Correlate findings to the timeline; map each to ATT&CK; extract IOCs.
```

## Validation
- Verify acquisition and copy hashes; evidence from an unverified image is not
  defensible.
- Corroborate each key event across at least two artifact sources (e.g., execution
  artifact + timeline + persistence entry) before asserting it.
- Flag MACB timestamp anomalies as possible timestomping rather than trusting times
  blindly.
- Record exact tools/commands so another examiner can reproduce the result.

## Expected Output
- A verified disk image with acquisition metadata and hashes.
- A timeline of relevant events anchored to the activity window.
- Findings: execution, persistence, file activity, anti-forensics, user activity —
  each with evidence and an ATT&CK mapping.
- An IOC set for sweeping other systems.

## False Positives
- Legitimate admin tools and scheduled tasks resembling attacker persistence —
  compare to a known-good baseline.
- Timestamp oddities from backups, syncing, or imaging rather than timestomping.
- Browser/recent-file artifacts from normal use, not the intrusion.

## Remediation
- Feed IOCs to EDR/SIEM to scope the incident; support containment and eradication
  of confirmed persistence under the IR plan.
- Preserve the image and notes for the case record and legal process.
- Recommend detections/hardening for the observed techniques (e.g., autostart
  monitoring, scheduled-task auditing, log-clearing alerts).

## Reporting
```
Disk Forensic Triage
Case/Authorization: <id>   Device: <...>   OS/FS: <...>
Acquisition: tool | UTC time | operator | image SHA-256 (verify log)
Timeline window: <start–end> with key events
Findings: (per item) artifact | evidence | ATT&CK ID | significance
Execution: <...>   Persistence: <...>   File activity: <...>
Anti-forensics: <log clearing / timestomping / wiping>
IOCs: <hashes, paths, indicators>
Chain of custody: <handling record>
```

## References
- NIST SP 800-86 (Guide to Integrating Forensic Techniques into IR):
  https://csrc.nist.gov/pubs/sp/800/86/final
- SANS Windows Forensic Analysis poster:
  https://www.sans.org/posters/windows-forensic-analysis/
- MITRE ATT&CK: https://attack.mitre.org/
