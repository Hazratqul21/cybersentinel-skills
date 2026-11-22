---
name: network-reconnaissance
description: Discover live hosts, open ports, and services across an authorized network range using host discovery, port scanning, and service/version detection, producing a scoped inventory for follow-on testing.
version: 1.0.0
category: red-team
tags: [network-security, reconnaissance, scanning, enumeration]
authorization_required: true
destructive: false
mitre_attack: [T1595, T1595.001, T1595.002, T1046]
references:
  - https://nmap.org/book/man.html
  - https://attack.mitre.org/techniques/T1046/
  - https://owasp.org/www-project-web-security-testing-guide/
---

# Network Reconnaissance

## Purpose
Enumerate an authorized network's live hosts, exposed ports, and running
services (with versions) to build an accurate inventory and attack-surface map
for subsequent, more targeted testing. Prioritize accuracy and low impact.

## Prerequisites
- Signed authorization naming exact in-scope IP ranges/CIDRs and exclusions.
- `nmap` (and optionally `masscan` for large ranges), plus `dig`/`nslookup`.
- Network access/vantage point as agreed (external, internal, or VPN).
- Approval for scan intensity and timing windows.

## Scope & Authorization
- **Never scan ranges you are not explicitly authorized to scan.** Confirm CIDRs
  and out-of-scope IPs (shared infrastructure, third parties, ICS/OT, fragile
  devices) in writing.
- Use conservative timing by default; aggressive scans can disrupt fragile
  hosts, IoT/OT, and printers. Exclude known-fragile assets.
- Avoid intrusive NSE scripts (`exploit`, `dos`, brute) unless explicitly
  authorized; default to `default,safe` script categories.
- Coordinate windows and keep the engagement contact reachable during scans.

## Methodology
1. **Range validation** — confirm scope, split large ranges, set exclusions.
2. **Host discovery** — identify live hosts (ICMP, ARP on local segment, TCP/UDP
   probes) before deep scanning to limit noise.
3. **Port scanning** — TCP SYN scan of relevant ports; staged full-range only
   where authorized. UDP selectively (slow, noisy) for key services.
4. **Service/version detection** — fingerprint services and versions on open
   ports; grab banners.
5. **Light enumeration** — safe NSE scripts for discovered services (e.g., TLS
   info, HTTP titles) — no exploitation.
6. **Correlate** — map hosts↔services↔versions; flag notable exposures
   (management interfaces, legacy protocols, default services).

## Execution Workflow
> Replace `10.0.0.0/24` with the authorized range. Start light; escalate only
> with approval.

```bash
# 1. Host discovery (no port scan yet)
nmap -sn -PE -PP -PS22,80,443 10.0.0.0/24 -oA discovery

# 2. Extract live hosts
grep "Up" discovery.gnmap | awk '{print $2}' > live.txt

# 3. Fast top-ports TCP SYN scan on live hosts (conservative timing)
sudo nmap -sS --top-ports 1000 -T3 -iL live.txt -oA tcp_top

# 4. Service/version detection + safe scripts on open ports only
sudo nmap -sS -sV -sC --version-light -T3 -iL live.txt -oA services

# 5. Targeted UDP for key services (slow; keep small)
sudo nmap -sU -T3 --top-ports 20 -iL live.txt -oA udp_top

# (Large external ranges, if authorized) masscan for fast discovery, then
# confirm/enumerate with nmap -sV on the hits only:
# sudo masscan 203.0.113.0/24 -p1-65535 --rate 1000 -oL masscan.txt
```

## Validation
- Confirm "open" ports with a service/version scan, not just a SYN result
  (filtered vs open-filtered ambiguity).
- Corroborate banners/versions; a single probe can misidentify a service behind
  a proxy or honeypot.
- Re-scan anomalies; rule out transient firewall/IPS behavior.
- Keep raw `-oA` outputs as evidence (normal/grepable/XML).

## Expected Output
- Host/service inventory: IP, hostname, port, protocol, state, service, version,
  banner, notable flags, scope status.
- Lists of live hosts and of high-interest exposures (RDP/SMB/SSH on internet,
  databases, management/admin, legacy protocols like Telnet/FTP).
- Evidence: nmap `-oA` sets, masscan logs.

## False Positives
- **Firewall/IPS behavior** can make all ports appear open or filtered; validate
  with `-sV` and alternate probes.
- **Honeypots** present fake services — note inconsistent fingerprints.
- Load balancers/NAT can make many IPs look identical or hide origins.
- UDP scans are unreliable (open|filtered) — confirm with service probes.
- Stale DNS can point names at decommissioned hosts.

## Remediation
Guidance for the asset owner:
- Close/restrict unnecessary exposed ports and services; default-deny at the
  perimeter and segment internal networks.
- Remove legacy/cleartext protocols (Telnet, FTP, unencrypted management).
- Put management interfaces (RDP, SSH, DB, admin panels) behind VPN/bastion and
  MFA; never expose to the internet directly.
- Patch and standardize service versions; remove end-of-life software.
- Monitor for and alert on scanning and anomalous service exposure.

## Reporting
```
Title: Network Reconnaissance — Host & Service Inventory
Authorization: <id>   Scope: <CIDRs>   Exclusions: <...>   Window: <...>
Summary: <N> live hosts, <N> open services, <N> high-interest exposures.
Methodology: discovery -> TCP/UDP scan -> service detection; timing used.
Inventory: (table) IP | host | port/proto | service | version | flags | scope
High-interest exposures: asset, exposure, risk, recommended action, evidence.
Remediation: prioritized (above).
Appendix: tool versions, raw nmap/masscan outputs.
```

## References
- Nmap Reference Guide: https://nmap.org/book/man.html
- MITRE ATT&CK T1046 (Network Service Discovery):
  https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1595 (Active Scanning): https://attack.mitre.org/techniques/T1595/
