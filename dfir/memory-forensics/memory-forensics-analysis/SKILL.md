---
name: memory-forensics-analysis
description: Acquire and analyze volatile memory from an authorized system to find malicious processes, injected code, network connections, credentials, and rootkit artifacts, preserving chain of custody and mapping findings to MITRE ATT&CK with IOCs for the broader investigation.
version: 1.0.0
category: dfir
tags: [dfir, memory-forensics, incident-response, malware-analysis, volatility]
authorization_required: false
destructive: false
mitre_attack: [T1055, T1003, T1057, T1036]
references:
  - https://volatilityfoundation.org/
  - https://csrc.nist.gov/pubs/sp/800/86/final
  - https://attack.mitre.org/
---

# Memory Forensics Analysis

## Purpose
Acquire and analyze a system's volatile memory (RAM) during an authorized
investigation to uncover evidence that never touches disk: running and hidden
processes, injected or hollowed code, active network connections, loaded drivers,
in-memory credentials, and command history. Produce reproducible findings, IOCs,
and ATT&CK mappings that drive scoping and containment.

## Prerequisites
- Authorization to investigate the host (incident response authority or owner
  consent) and an evidence-handling policy.
- A forensically sound acquisition method and sufficient storage for a full dump.
- The OS type/version and, ideally, the matching symbols/profile for the analysis
  tool (e.g., Volatility 3 symbol tables).
- A clean, isolated analysis workstation; never analyze on the suspect host.

## Scope & Authorization
- Confirm you are authorized to collect memory from this specific system; memory
  often contains sensitive data (credentials, keys, personal data) — handle it
  under the evidence policy.
- **Order of volatility:** capture memory before shutdown/disk imaging when safe;
  a running compromise may be lost on reboot.
- Preserve **chain of custody**: hash the image at acquisition, document who/what/
  when/where, and work only on verified copies.
- Treat the dump as sensitive evidence: restrict access and storage.

## Methodology
1. **Acquire** — capture RAM with a validated tool; record the acquisition tool,
   time, operator, and a cryptographic hash of the image.
2. **Verify & profile** — confirm the hash, then identify the OS/kernel so the
   analysis tool uses the correct symbols.
3. **Process analysis** — enumerate processes and parent/child relationships; find
   hidden/unlinked processes and suspicious lineage (T1057, T1036).
4. **Injection & hollowing** — look for private executable memory, unmapped code,
   and mismatched image paths (T1055).
5. **Network** — recover active/closed connections and owning processes.
6. **Persistence & modules** — review loaded drivers/modules and autostart traces.
7. **Credentials & secrets** — identify in-memory credential exposure (T1003)
   relevant to lateral-movement scoping.
8. **Strings/IOCs** — extract suspicious strings, URLs, and artifacts; derive IOCs.

## Execution Workflow
> Analyze a verified copy on an isolated workstation. Record every tool/plugin and
> its output for reproducibility.

```
1. Acquire + hash:
   - Capture full RAM with a validated acquirer; compute SHA-256; log metadata.
   - Copy image; verify the copy's hash matches. Work on the copy.

2. Identify OS/symbols for the analysis framework (e.g., Volatility 3).

3. Process triage:
   - List processes + tree; flag unusual parents (e.g., office app -> shell),
     hidden/terminated-but-present processes, and odd paths.

4. Injection:
   - Scan for injected/private-exec regions and image-path mismatches.

5. Network:
   - List connections; correlate owning PID to the process triage.

6. Modules/persistence:
   - Review loaded drivers/modules for unsigned/unknown entries.

7. Extract: suspicious strings, command lines, URLs, files -> IOC list.
   Map each confirmed finding to an ATT&CK technique.
```

## Validation
- Confirm the image hash at acquisition and before analysis; findings from an
  unverified image are not reliable evidence.
- Corroborate a suspicious process with at least two signals (e.g., injected memory
  **and** anomalous network/lineage) before calling it malicious.
- Reproduce each key finding (same plugin/parameters → same result) and record the
  exact commands.
- Distinguish artifacts of the acquisition tool itself from attacker activity.

## Expected Output
- A verified memory image with acquisition metadata and hashes.
- A findings list: malicious/suspicious processes, injection, connections,
  persistence, credential exposure — each with evidence and an ATT&CK mapping.
- An IOC set (hashes, paths, IPs/domains, process names) for sweeping the estate.
- A timeline fragment to merge into the incident timeline.

## False Positives
- Legitimate software that injects or hooks (some security/EDR agents, installers)
  resembling malicious injection — validate against known-good.
- Expected system processes with unusual-looking memory — compare to a baseline.
- Strings/URLs present from benign browsing or cached content, not the intrusion.

## Remediation
- Feed IOCs to EDR/SIEM to scope the compromise across other hosts.
- Support containment (isolate affected hosts, reset exposed credentials found in
  memory) under the IR plan.
- Preserve the image and analysis notes for the case record and any legal process.
- Recommend detections for the observed techniques (e.g., injection, suspicious
  parent-child chains).

## Reporting
```
Memory Forensics Analysis
Case/Authorization: <id>   Host: <...>   OS: <...>
Acquisition: tool | UTC time | operator | image SHA-256 (verify log)
Findings: (per item) artifact | evidence (plugin/output) | ATT&CK ID | significance
Processes/injection: <...>   Network: <...>   Persistence/modules: <...>
Credential exposure: <...>
IOCs: <hashes, paths, IPs/domains, process names>
Timeline: <key events with timestamps>
Chain of custody: <handling record>
```

## References
- Volatility Foundation: https://volatilityfoundation.org/
- NIST SP 800-86 (Guide to Integrating Forensic Techniques into IR):
  https://csrc.nist.gov/pubs/sp/800/86/final
- MITRE ATT&CK: https://attack.mitre.org/
