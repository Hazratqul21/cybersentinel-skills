---
name: skill-name-here
description: One-line description of what this skill does and when an agent should use it (20-500 chars).
version: 1.0.0
category: red-team
tags: [example-tag]
authorization_required: true
destructive: false
mitre_attack: [T1190]
owasp: [A03:2021]
cwe: [CWE-89]
references:
  - https://example.com/official-reference
---

# Skill Name Here

> Template. Copy this directory, rename it to your skill's canonical name
> (lowercase-hyphen, matching the `name` field), and fill every section with
> substantive, verified content. Remove this note and all `<...>` placeholders.
> Set `authorization_required: true` for any offensive/active skill.

## Purpose
<What the skill accomplishes and the value it provides.>

## Prerequisites
<Tools, access, and knowledge required.>

## Scope & Authorization
<Explicit authorization + scope-validation requirements. Non-destructive defaults.>

## Methodology
<The technical approach, in phases.>

## Execution Workflow
<Concrete, ordered steps the agent follows. Use placeholders, not real targets.>

## Validation
<How to confirm a finding is real: reproducibility and proof rules.>

## Expected Output
<Artifacts and data the skill produces.>

## False Positives
<Common false positives and how to rule them out.>

## Remediation
<Defensive fixes and mitigations.>

## Reporting
<A reusable reporting template.>

## References
<Links to official/primary sources.>
