# Security Policy

## Intended use

CyberSentinel Skills exists for **authorized** security work only:

- Authorized penetration testing and red/purple team engagements
- Defensive (blue team) operations, detection engineering, and DFIR
- Security research in controlled or lab environments
- Education and training

**You are responsible for ensuring you have explicit, written authorization for
any system you test.** Unauthorized access to computer systems is illegal in most
jurisdictions. Every offensive skill requires `authorization_required: true` and
a *Scope & Authorization* section; honor them.

## Safety principles enforced in this repository

- **Explicit authorization** gates for all offensive/active skills.
- **Non-destructive defaults** — skills prefer read-only proofs; destructive steps
  must be clearly marked and operator-gated.
- **Lab-first examples** using placeholders (`example.com`, RFC 1918 ranges, `TARGET`).
- **No automatic external target execution**, no credential theft, no uncontrolled
  persistence, no destructive payloads, no working malware, no embedded live C2.
- **Paired defense** — offensive techniques ship with detection and remediation.
- A **dangerous-script scanner** (`cybersentinel validate`) blocks patterns such as
  `rm -rf /`, `mkfs`, raw block-device writes, fork bombs, and curl-pipe-to-shell.

## What will not be accepted

Contributions whose primary purpose is unauthorized harm, including: ready-to-run
malware or ransomware, credential stealers/keyloggers aimed at third parties,
mass-exploitation automation against arbitrary targets, DoS tooling, or detection
evasion intended for malicious use. Dual-use security tooling is accepted only
with clear authorized-use framing, safety gating, and defensive guidance.

## Reporting a vulnerability

If you find a security issue **in this project's tooling** (the validator, CLI, or
CI), please report it privately rather than opening a public issue:

1. Open a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories)
   on the repository, or
2. Email the maintainers (see repository metadata).

Please include reproduction steps and affected versions. We aim to acknowledge
reports promptly and coordinate disclosure.

## Handling of findings produced by skills

Treat any data, credentials, or vulnerabilities discovered while running these
skills as sensitive. Store evidence securely, share on a need-to-know basis, and
follow the engagement's disclosure and data-handling rules.
