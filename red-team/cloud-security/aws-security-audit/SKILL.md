---
name: aws-security-audit
description: Audit an authorized AWS account for common security misconfigurations — public S3, over-permissive IAM, exposed credentials, unrestricted security groups, and missing logging — using read-only API calls mapped to CIS AWS Benchmark, with remediation.
version: 1.0.0
category: red-team
tags: [cloud-security, aws, iam, configuration-audit, cis-benchmark]
authorization_required: true
destructive: false
mitre_attack: [T1530, T1078.004, T1580, T1526]
references:
  - https://www.cisecurity.org/benchmark/amazon_web_services
  - https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
  - https://attack.mitre.org/matrices/enterprise/cloud/
---

# AWS Security Audit

## Purpose
Assess an authorized AWS account for the misconfigurations that most often lead
to compromise — public storage, over-privileged IAM, exposed access keys,
unrestricted network exposure, and disabled logging — and produce prioritized,
CIS-aligned remediation. Emphasis is on **read-only** API enumeration.

## Prerequisites
- Signed authorization and the in-scope account ID(s)/regions.
- Read-only credentials (ideally the AWS managed `SecurityAudit` or
  `ViewOnlyAccess` policy) for the audited account.
- AWS CLI configured; optionally Prowler or ScoutSuite for breadth.
- Familiarity with IAM, S3, EC2/VPC, CloudTrail, and the CIS AWS Benchmark.

## Scope & Authorization
- Require written authorization naming the account(s) and regions; cloud audits
  touch production infrastructure.
- **Read-only.** Use `Describe*`/`List*`/`Get*` calls only. Do **not** create,
  modify, or delete resources, change policies, or exfiltrate data. If using
  Prowler/ScoutSuite, run in their read-only default mode.
- Use scoped audit credentials, not root or admin; never generate or expose new
  access keys as part of the audit.
- Treat findings (keys, data locations) as sensitive; record references, not
  secret material.

## Methodology
1. **Account & identity** — root usage/MFA, IAM users, access-key age, MFA
   coverage, password policy.
2. **IAM policy review** — over-permissive policies (`*:*`), privilege-escalation
   paths, unused credentials, inline/attached admin policies.
3. **Storage exposure** — public S3 buckets/objects, bucket policies/ACLs,
   Block Public Access settings, default encryption.
4. **Network exposure** — security groups open to `0.0.0.0/0` on sensitive ports
   (22, 3389, databases), public RDS/snapshots.
5. **Logging & monitoring** — CloudTrail enabled (multi-region), Config, GuardDuty,
   log integrity validation.
6. **Secrets exposure** — access keys in EC2 user-data, Lambda env vars, public
   AMIs/snapshots.
7. **Map to CIS AWS Benchmark** controls and severity.

## Execution Workflow
> Read-only. Set `AWS_PROFILE` to the scoped audit profile. Iterate regions as
> needed.

```bash
export AWS_PROFILE=audit-readonly
aws sts get-caller-identity          # confirm you're in the right account

# 1. Root/MFA + credential hygiene
aws iam get-account-summary
aws iam generate-credential-report >/dev/null; sleep 3
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv
#    Review: root MFA, access_key_last_used, password_enabled, mfa_active.

# 2. Over-permissive IAM policies (look for Action/Resource "*")
for p in $(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text); do
  v=$(aws iam get-policy --policy-arn "$p" --query 'Policy.DefaultVersionId' --output text)
  echo "== $p"; aws iam get-policy-version --policy-arn "$p" --version-id "$v" \
    --query 'PolicyVersion.Document' --output json
done

# 3. Public S3 exposure
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "== $b"
  aws s3api get-public-access-block --bucket "$b" 2>/dev/null
  aws s3api get-bucket-acl --bucket "$b" --query 'Grants[?Grantee.URI!=`null`]' 2>/dev/null
done

# 4. Security groups open to the world on sensitive ports
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
  --output table

# 5. CloudTrail coverage
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,LogFileValidationEnabled]' --output table

# Optional breadth (read-only):
#   prowler aws --profile audit-readonly
#   python scout.py aws --profile audit-readonly
```

## Validation
- Confirm each finding from the authoritative API response (e.g., an S3 Grant to
  `AllUsers`, a security-group rule with `0.0.0.0/0` on port 22) rather than a
  tool summary alone.
- Check Block Public Access at both account and bucket level before declaring a
  bucket "public."
- Distinguish intended public assets (static sites, by design) from accidental
  exposure — confirm with the owner.
- Keep raw API outputs / tool reports as evidence.

## Expected Output
- Findings mapped to CIS controls: misconfiguration, affected resource(s),
  exposure/impact, severity, remediation.
- Credential-hygiene summary (root MFA, key age, MFA coverage).
- IAM over-permission and privilege-escalation path list.
- Logging/monitoring coverage gaps.
- Evidence: cred report, API outputs, Prowler/ScoutSuite report.

## False Positives
- S3 buckets that are **intentionally** public (static hosting) — confirm intent.
- Security-group rules fronted by a WAF/ALB or restricted elsewhere — verify
  effective exposure.
- Broad-looking IAM policies scoped by conditions/permission boundaries — read the
  whole policy, including `Condition`.
- Prowler/ScoutSuite "FAIL" items that reflect accepted risk — reconcile with the
  owner's baseline.

## Remediation
- Enforce MFA everywhere (root included); remove/rotate unused and old access
  keys; prefer roles/STS over long-lived keys.
- Apply least-privilege IAM; remove `*:*`; use permission boundaries and SCPs;
  eliminate privilege-escalation paths.
- Enable S3 Block Public Access account-wide; default-encrypt buckets; remove
  public ACLs/policies unless explicitly required.
- Restrict security groups to specific sources; never expose SSH/RDP/databases to
  `0.0.0.0/0`; put admin access behind SSM/bastion.
- Enable multi-region CloudTrail with log validation, AWS Config, and GuardDuty;
  centralize and protect logs.
- Scan for secrets in user-data, env vars, and public AMIs/snapshots; rotate any
  exposed credential.

## Reporting
```
Title: AWS Security Configuration Audit
Authorization: <id>   Account(s): <...>   Regions: <...>   Credentials: read-only
Summary: <N> critical, <N> high findings; key exposure themes.
Findings: (per item) CIS ref | misconfig | resource | exposure/impact | severity |
          remediation
Identity hygiene: root MFA, key age, MFA coverage, password policy.
IAM risks: over-permissive policies, escalation paths.
Logging gaps: CloudTrail/Config/GuardDuty coverage.
Remediation roadmap: prioritized (above).
Appendix: credential report, raw API outputs, tool reports, versions.
```

## References
- CIS Amazon Web Services Benchmark:
  https://www.cisecurity.org/benchmark/amazon_web_services
- AWS Well-Architected Security Pillar:
  https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/
