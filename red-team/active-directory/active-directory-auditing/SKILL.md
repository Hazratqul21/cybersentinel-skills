---
name: active-directory-auditing
description: Audit an authorized Active Directory environment for misconfigurations and attack paths — Kerberoastable accounts, AS-REP roasting, dangerous ACLs, delegation issues, and privileged-group exposure — read-only first, with remediation.
version: 1.0.0
category: red-team
tags: [active-directory, windows-security, enumeration, privilege-escalation]
authorization_required: true
destructive: false
mitre_attack: [T1087.002, T1558.003, T1558.004, T1069.002, T1484]
references:
  - https://attack.mitre.org/techniques/T1558/003/
  - https://learn.microsoft.com/en-us/defender-for-identity/
  - https://bloodhound.readthedocs.io/
---

# Active Directory Auditing

## Purpose
Identify misconfigurations and privilege-escalation / lateral-movement paths in
an authorized Active Directory (AD) environment and translate them into concrete
remediation. Emphasis is on **read-only enumeration and attack-path analysis**,
not exploitation, so defenders get an accurate risk picture with minimal impact.

## Prerequisites
- Signed authorization and in-scope domain(s)/forest, with a provided audit
  account (ideally low-privileged domain user) or assumed-breach context.
- Tooling: BloodHound/SharpHound (or `bloodhound-python`), PowerView, AD module,
  `ldapsearch`, `impacket` suite (`GetUserSPNs`, `GetNPUsers`) for read checks.
- A controlled test host; awareness of MDI/Defender for Identity monitoring.

## Scope & Authorization
- Require written authorization; AD actions are high-visibility and can trigger
  security alerts — coordinate with the blue team / detection owners.
- **Default to read-only.** Enumeration (LDAP queries, BloodHound collection) is
  non-destructive. Do **not** crack tickets, relay, modify ACLs/GPOs, or create
  persistence under an audit-only engagement.
- If credential-attack *validation* (e.g., actually Kerberoasting and cracking)
  is authorized, keep it offline and scoped; never run broad password spraying
  that could lock accounts.
- Avoid actions that generate account lockouts or service disruption.

## Methodology
1. **Domain enumeration** — domains, trusts, OUs, users, groups, computers,
   GPOs, password policy, functional levels.
2. **Privileged exposure** — members of Domain/Enterprise/Schema Admins,
   nested-group creep, stale/over-privileged accounts, admin count.
3. **Kerberos exposure** — SPN accounts (Kerberoastable), accounts with
   "Do not require Kerberos preauth" (AS-REP roastable).
4. **Delegation** — unconstrained, constrained, and resource-based constrained
   delegation misconfigurations.
5. **ACL analysis** — dangerous rights (GenericAll/Write, WriteDacl, WriteOwner,
   AddMember) on users/groups/computers/GPOs; AdminSDHolder.
6. **Attack-path graphing** — import into BloodHound; identify shortest paths to
   high-value targets.
7. **Hygiene** — password policy, LAPS coverage, stale objects, SMB signing,
   legacy auth.

## Execution Workflow
> Read-only collection. Use the provided audit account. Coordinate with
> detection owners before running.

```bash
# BloodHound collection (read-only LDAP/SMB) from Linux:
bloodhound-python -u 'audit' -p 'REDACTED' -d example.local \
  -ns 10.0.0.10 -c DCOnly -o bh_output
#   -c DCOnly minimizes host touching (no session/loggedon collection).

# Kerberoastable SPN accounts (enumerate; do NOT crack under audit-only):
impacket-GetUserSPNs example.local/audit:REDACTED -dc-ip 10.0.0.10
#   Add -request only if ticket extraction+offline cracking is authorized.

# AS-REP roastable (no-preauth) users — enumeration:
impacket-GetNPUsers example.local/ -usersfile users.txt -dc-ip 10.0.0.10 -no-pass
```

```powershell
# PowerView (read-only) examples on a domain-joined test host:
Get-DomainUser -SPN | Select samaccountname          # Kerberoastable
Get-DomainUser -PreauthNotRequired | Select samaccountname
Get-DomainComputer -Unconstrained | Select name      # unconstrained delegation
Get-DomainGroupMember "Domain Admins" -Recurse
```

Then import `bh_output` into BloodHound and run the built-in analytics
(Shortest Paths to Domain Admins, Kerberoastable→DA, dangerous ACLs).

## Validation
- Confirm each finding against AD data directly (LDAP attribute, group
  membership, ACE) — don't rely on a single tool's label.
- For delegation/ACL findings, document the exact object, right, and principal.
- Distinguish *theoretical* paths from *exploitable* ones (account enabled, in
  use, reachable) and note prerequisites.
- Keep raw collection outputs as evidence.

## Expected Output
- Findings list: misconfiguration type, affected object(s)/principal(s), the
  attack path it enables, prerequisites, severity, remediation.
- BloodHound graph exports of key paths to high-value targets.
- Privileged-access and delegation inventories; hygiene summary (LAPS, policy).
- Evidence: query outputs, screenshots of paths.

## False Positives
- SPNs on accounts with strong, managed passwords (gMSA) are low risk — note it.
- Expected administrative ACLs (tiered admin model) are not findings — baseline
  against the intended design.
- Disabled/stale accounts may appear in paths but not be exploitable — mark
  status.
- BloodHound edges can reflect historical sessions; confirm current state.

## Remediation
- Enforce tiered administration and least privilege; shrink privileged groups
  and remove nesting creep.
- Use **gMSA** for service accounts and long, random passwords to neutralize
  Kerberoasting; require Kerberos preauth (remove "do not require preauth").
- Remove unconstrained delegation; prefer resource-based constrained delegation,
  and mark sensitive accounts "cannot be delegated."
- Fix dangerous ACLs (GenericAll/WriteDacl/WriteOwner) on tier-0 objects and
  GPOs; monitor AdminSDHolder.
- Deploy **LAPS**/Windows LAPS for local admin passwords; enable SMB signing and
  disable legacy protocols (NTLMv1, LLMNR/NBT-NS).
- Enable Microsoft Defender for Identity / robust Kerberos and LDAP auditing.

## Reporting
```
Title: Active Directory Security Audit
Authorization: <id>   Domain/Forest: <...>   Audit account: <low-priv>
Summary: <N> critical paths to Domain Admin; key misconfig classes.
Findings: (per item) type | object/principal | attack path enabled | prereqs |
          severity | remediation
Privileged access: Domain Admins and tier-0 membership review.
Attack paths: BloodHound graph refs (e.g., Kerberoast -> DA).
Hygiene: password policy, LAPS coverage, legacy auth, SMB signing.
Remediation roadmap: prioritized (above).
Appendix: raw collection outputs, tool versions, detection coordination notes.
```

## References
- MITRE ATT&CK T1558.003 (Kerberoasting): https://attack.mitre.org/techniques/T1558/003/
- Microsoft Defender for Identity: https://learn.microsoft.com/en-us/defender-for-identity/
- BloodHound documentation: https://bloodhound.readthedocs.io/
