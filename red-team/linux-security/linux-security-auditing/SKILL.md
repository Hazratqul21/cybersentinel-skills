---
name: linux-security-auditing
description: Audit an authorized Linux host for privilege-escalation vectors and hardening gaps — SUID/SGID, sudo and capability misconfigurations, writable cron/services, weak permissions, and kernel exposure — read-only enumeration with remediation.
version: 1.0.0
category: red-team
tags: [linux-security, privilege-escalation, hardening, host-audit]
authorization_required: true
destructive: false
mitre_attack: [T1548.001, T1548.003, T1053.003, T1068, T1222.002]
cwe: [CWE-250, CWE-732]
references:
  - https://gtfobins.github.io/
  - https://attack.mitre.org/techniques/T1548/
  - https://www.cisecurity.org/benchmark/distribution_independent_linux
---

# Linux Security Auditing

## Purpose
Enumerate privilege-escalation opportunities and hardening weaknesses on an
authorized Linux host, from an assumed low-privileged shell, and provide
prioritized remediation. Focus on **safe, read-only enumeration** that reveals
*how* a local attacker could escalate — without actually escalating or modifying
the system.

## Prerequisites
- Signed authorization and in-scope host(s).
- A shell on the target (assumed-breach) at normal user privilege.
- Tooling (optional, use read-only modes): LinPEAS, `linux-exploit-suggester`,
  `pspy` for process monitoring; otherwise standard coreutils.
- Knowledge of GTFOBins for interpreting exploitable binaries.

## Scope & Authorization
- Require written authorization for host access and for running enumeration
  scripts; third-party automated scripts should be reviewed before use.
- **Read-only / non-destructive.** Enumerate and document vectors; do **not**
  actually escalate to root, modify system files, install tools persistently,
  or run exploit code unless privilege-escalation *validation* is explicitly
  authorized and scoped.
- Avoid noisy or resource-heavy scans on production; coordinate timing.
- Treat any discovered secrets as sensitive; record location, not the value.

## Methodology
1. **Context** — user, groups, sudo rights, environment, kernel/distro version.
2. **SUID/SGID & capabilities** — find set-uid/gid binaries and file
   capabilities; cross-reference GTFOBins for abuse potential.
3. **sudo** — `sudo -l` rules, NOPASSWD entries, exploitable allowed commands,
   known `sudo` CVEs (e.g., Baron Samedit) by version.
4. **Scheduled tasks & services** — writable cron scripts/dirs, systemd units,
   PATH issues, wildcard abuse.
5. **Weak permissions** — writable files in privileged paths, `/etc/passwd`,
   `/etc/shadow` readability, writable `/etc/*` config, service binaries.
6. **Credentials & secrets** — history files, config files, keys, tokens,
   world-readable backups.
7. **Kernel/exploit exposure** — version vs known local-privesc CVEs (DirtyPipe,
   PwnKit, etc.) — identify, don't run.
8. **Containers** — if containerized, check for docker group, privileged flags,
   mounted sockets, capabilities.

## Execution Workflow
> Read-only enumeration. Interpret, don't exploit. Coordinate before running on
> production.

```bash
# 1. Context
id; sudo -n -l 2>/dev/null; uname -a; cat /etc/os-release

# 2. SUID / SGID binaries (compare against GTFOBins)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# 3. File capabilities
getcap -r / 2>/dev/null

# 4. Writable cron / world-writable in sensitive paths
ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null
find /etc /usr/local -writable -type f 2>/dev/null

# 5. Sensitive file permissions
ls -l /etc/passwd /etc/shadow 2>/dev/null
find / -name "*.bak" -o -name "id_rsa" -o -name "*.pem" 2>/dev/null | head

# 6. Credentials in history/config (record locations, not secrets)
grep -RinE "password|secret|token|api[_-]?key" ~/.bash_history ~/.*rc 2>/dev/null | head

# 7. Optional automated (read-only):
#    ./linpeas.sh -q            # review output; it does not modify the system
#    ./les.sh                   # linux-exploit-suggester: maps kernel CVEs
#    ./pspy64                   # watch cron/root processes (passive)
```

## Validation
- For each vector, confirm the *concrete* condition: the exact SUID binary +
  GTFOBins technique, the specific NOPASSWD rule, the writable file + how a
  privileged process consumes it.
- Distinguish a real path (writable file actively run by root) from a theoretical
  one; note prerequisites.
- Match kernel CVEs to the exact version and confirm the exploit precondition
  rather than assuming applicability.

## Expected Output
- Prioritized findings: vector type, exact artifact (path/rule/binary), the
  escalation it enables, prerequisites, severity, remediation.
- Host context summary (kernel, distro, patch level).
- Inventory of secrets/locations found (redacted values).
- Evidence: command outputs (LinPEAS/les logs if used).

## False Positives
- Many SUID binaries are legitimate and **not** abusable — only GTFOBins-listed
  and context-exploitable ones matter.
- `linux-exploit-suggester` lists *candidate* CVEs by version; many won't apply
  (patched, mitigations, config) — verify.
- Writable files that no privileged process consumes are low risk.
- "Secrets" in sample/config templates may be placeholders.

## Remediation
- Remove or restrict unnecessary SUID/SGID bits and file capabilities; audit
  against a known-good baseline.
- Tighten sudo: remove NOPASSWD and risky allowed commands; keep `sudo` patched;
  use `secure_path`.
- Fix file permissions: no world/group-writable scripts in cron/systemd/privileged
  paths; correct `/etc` ownership; protect `/etc/shadow`.
- Remove plaintext secrets; use a secrets manager; rotate anything exposed.
- Patch the kernel and userland; enable automatic security updates where viable.
- Apply CIS Linux Benchmark hardening and host-based monitoring/auditd rules.
- For containers: drop capabilities, avoid `--privileged`, don't mount the Docker
  socket, run as non-root.

## Reporting
```
Title: Linux Host Security Audit (Privilege Escalation & Hardening)
Authorization: <id>   Host(s): <...>   Access: assumed-breach (user)
Context: kernel <...>, distro <...>, patch level <...>
Findings: (per item) vector | artifact (path/rule) | escalation enabled |
          prereqs | severity | remediation
Secrets exposure: locations (redacted), recommended rotation.
Kernel/CVE exposure: applicable candidates with preconditions.
Remediation roadmap: prioritized (above).
Appendix: command/LinPEAS outputs, tool versions.
```

## References
- GTFOBins: https://gtfobins.github.io/
- MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism):
  https://attack.mitre.org/techniques/T1548/
- CIS Distribution Independent Linux Benchmark:
  https://www.cisecurity.org/benchmark/distribution_independent_linux
