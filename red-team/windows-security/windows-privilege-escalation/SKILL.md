---
name: windows-privilege-escalation
description: Enumerate privilege-escalation vectors on an authorized Windows host from a low-privileged context — service and registry misconfigurations, token privileges, credential exposure, and patch gaps — read-only first, with remediation.
version: 1.0.0
category: red-team
tags: [windows-security, privilege-escalation, host-audit, enumeration]
authorization_required: true
destructive: false
mitre_attack: [T1068, T1134, T1574, T1078, T1055]
cwe: [CWE-250, CWE-269]
references:
  - https://attack.mitre.org/techniques/T1068/
  - https://learn.microsoft.com/en-us/windows/security/
  - https://lolbas-project.github.io/
---

# Windows Privilege Escalation

## Purpose
Identify local privilege-escalation opportunities on an authorized Windows host
from an assumed low-privileged shell and provide prioritized remediation. Focus
is **read-only enumeration** that reveals *how* escalation would be possible —
without actually escalating or modifying the system.

## Prerequisites
- Signed authorization and in-scope host(s).
- A shell on the target (assumed-breach) as a standard user.
- Tooling (read-only modes): WinPEAS, PowerUp/PrivescCheck, `whoami /all`,
  `accesschk` (Sysinternals); LOLBAS knowledge for interpreting findings.
- Awareness of EDR/Defender monitoring on the host.

## Scope & Authorization
- Require written authorization for host access and for running enumeration
  tools; third-party scripts should be reviewed and approved first.
- **Read-only / non-destructive.** Enumerate and document vectors; do **not**
  actually escalate, modify services/registry, drop persistence, or run exploit
  code unless escalation *validation* is explicitly authorized and scoped.
- Treat discovered credentials/secrets as sensitive — record location, not value.
- Coordinate with detection owners; these actions are frequently alerted on.

## Methodology
1. **Context** — current user, groups, privileges (`whoami /all`), integrity
   level, OS build/patch level, architecture.
2. **Token privileges** — exploitable privileges (SeImpersonate/SeAssignPrimary
   → "Potato" techniques, SeBackup/SeRestore, SeDebug) held by the account.
3. **Service misconfigurations** — unquoted service paths, weak service binary/
   config permissions, writable service executables, auto-start services.
4. **Registry & AutoRuns** — `AlwaysInstallElevated`, weak registry ACLs,
   writable Run keys, startup folders.
5. **DLL hijacking / missing binaries** — writable directories in service/app
   search paths.
6. **Credential exposure** — stored creds (cmdkey, Credential Manager),
   unattend/sysprep files, registry autologon, config files, PowerShell history.
7. **Patch gaps** — missing KBs vs known local-privesc CVEs (identify, don't run).

## Execution Workflow
> Read-only enumeration. Interpret, don't exploit. Coordinate before running.

```powershell
# 1. Context & privileges
whoami /all
systeminfo   # OS build/patch level
[Environment]::Is64BitProcess

# 2. Unquoted service paths with spaces (classic misconfig)
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match '^[^"].*\s.*\.exe' -and $_.PathName -notmatch '^"' } |
  Select-Object Name, PathName, StartMode

# 3. AlwaysInstallElevated (both hives must be 1 to be exploitable)
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null

# 4. Weak service permissions (requires accesschk.exe from Sysinternals)
#    accesschk.exe -uwcqv "Users" * /accepteula

# 5. Stored credentials / autologon
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null |
  Select-String "DefaultPassword"
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
```

```text
# Optional automated (read-only) collectors — review output, they enumerate only:
#   winPEASx64.exe
#   Import-Module .\PowerUp.ps1; Invoke-AllChecks
#   PrivescCheck.ps1 -Extended
```

## Validation
- For each vector confirm the concrete, exploitable condition: both
  `AlwaysInstallElevated` hives set, a writable service binary that runs as
  SYSTEM, the actual token privilege held, a writable path in a service's search
  order.
- Distinguish a real, actionable path from a theoretical one; note prerequisites
  (e.g., whether `SeImpersonate` plus a usable technique applies to the build).
- Match CVEs to the exact build number and confirm the exploit precondition.

## Expected Output
- Prioritized findings: vector type, exact artifact (service/registry/path/
  privilege), escalation enabled, prerequisites, severity, remediation.
- Host context summary (build, patch level, integrity, privileges).
- Inventory of exposed credentials/locations (redacted values).
- Evidence: command/WinPEAS outputs.

## False Positives
- Only **one** of the two `AlwaysInstallElevated` keys set → not exploitable.
- Unquoted service paths where no writable directory precedes the binary → not
  actionable.
- Weak permissions on services that don't run with high privilege → low risk.
- Automated tools flag *candidate* CVEs by build; verify the patch is truly
  missing and the precondition holds.
- "Credentials" in templates/sample files may be placeholders.

## Remediation
- Quote all service `ImagePath` values; fix service and binary ACLs so standard
  users cannot modify service executables or configs.
- Disable `AlwaysInstallElevated` (set both hives to 0 / remove).
- Remove writable directories from privileged search paths; prevent DLL hijacking.
- Remove stored plaintext credentials and autologon passwords; use LAPS for local
  admin; store secrets in a vault.
- Apply least privilege; remove unneeded sensitive token privileges from standard
  accounts; restrict `SeImpersonate` where feasible.
- Keep the OS patched; enable Defender/EDR, Attack Surface Reduction rules, and
  Credential Guard.

## Reporting
```
Title: Windows Host Privilege Escalation Audit
Authorization: <id>   Host(s): <...>   Access: assumed-breach (standard user)
Context: OS build <...>, patch level <...>, privileges <whoami /all summary>
Findings: (per item) vector | artifact | escalation enabled | prereqs | severity |
          remediation
Credential exposure: locations (redacted), rotation recommendation.
Patch/CVE exposure: applicable candidates with preconditions.
Remediation roadmap: prioritized (above).
Appendix: command/WinPEAS outputs, tool versions, detection coordination.
```

## References
- MITRE ATT&CK T1068 (Exploitation for Privilege Escalation):
  https://attack.mitre.org/techniques/T1068/
- Microsoft Windows Security docs: https://learn.microsoft.com/en-us/windows/security/
- LOLBAS Project: https://lolbas-project.github.io/
