---
name: threat-actor-profiling
description: Build an evidence-based profile of a threat actor relevant to an authorized organization from cited intelligence, cataloging their TTPs, tooling, targeting, and motivation, assessing relevance and confidence, and producing an ATT&CK-mapped profile that drives emulation and detection priorities.
version: 1.0.0
category: threat-intelligence
tags: [threat-intelligence, threat-actor, ttp, attribution, mitre-attack]
authorization_required: false
destructive: false
mitre_attack: [T1590, T1583]
references:
  - https://attack.mitre.org/groups/
  - https://www.cisa.gov/news-events/cybersecurity-advisories
  - https://www.first.org/global/sigs/cti/
---

# Threat Actor Profiling

## Purpose
Produce an evidence-based profile of a threat actor (or group/campaign) relevant to
an organization, drawing only on cited intelligence: their tactics, techniques, and
procedures, tooling, targeting, infrastructure patterns, and likely motivation.
Assess how relevant the actor is to the org and with what confidence, and output an
ATT&CK-mapped profile that prioritizes emulation, detection, and defensive
investment.

## Prerequisites
- A defined purpose and the organization's context (sector, geography, assets) to
  judge relevance.
- Access to credible intelligence sources (vendor and government reporting, ATT&CK
  group pages, ISAC/CTI feeds) and their publication dates.
- A structured analytic approach (e.g., explicit confidence levels and source
  grading) to avoid overclaiming.
- A place to record the profile with citations.

## Scope & Authorization
- This is an analysis task over authorized/intelligence sources; respect source
  licensing, TLP handling, and the org's disclosure rules.
- **Attribution is probabilistic.** State confidence and reasoning; do not assert
  attribution as fact without strong, corroborated evidence. Avoid naming
  individuals; focus on the actor's behavior and impact.
- Cite every claim to a dated source; distinguish primary reporting from secondary
  commentary.
- Keep internal/sensitive context (why this org cares) at the appropriate handling
  level.

## Methodology
1. **Define the question** — which actor/campaign and why (a sighting, sector
   targeting, a report); set the relevance criteria.
2. **Collect** — gather credible, dated reporting; record source and reliability.
3. **TTP catalog** — map the actor's reported techniques to ATT&CK across the kill
   chain; note their signature procedures and tooling (TA0042/TA0043).
4. **Targeting & motivation** — sectors, regions, objectives (espionage, financial,
   disruption) and typical initial-access methods.
5. **Infrastructure patterns** — hosting, domain, and operational habits useful for
   detection (without asserting live attribution of specific infra).
6. **Relevance assessment** — compare the actor's targeting/TTPs to the org's
   profile and existing coverage.
7. **Confidence** — grade each conclusion by source quality and corroboration.

## Execution Workflow
> Cite every claim to a dated source. Separate observation from assessment. Grade
> confidence explicitly.

```
1. Scope: actor/campaign + relevance criteria (sector, geo, assets).

2. Collect: credible dated reports; log source + reliability grade.

3. TTPs:
   - Extract techniques -> ATT&CK IDs; note signature procedures, malware, tooling.

4. Targeting/motivation:
   - Sectors, regions, objectives, typical initial access.

5. Relevance:
   - Does the actor target this org's sector/geo/tech? Overlap with current
     detection coverage?

6. Assess:
   - Per conclusion: confidence (high/med/low) + the evidence and any gaps.

7. Output profile with citations; recommend emulation/detection priorities.
```

## Validation
- Every TTP and claim traces to a cited, dated source; flag single-source or
  low-reliability claims as low confidence.
- Separate **observation** (what reporting says the actor did) from **assessment**
  (your inference); never present inference as observed fact.
- Check for source circularity (multiple reports citing one original) before
  treating corroboration as independent.
- Mark intelligence gaps explicitly rather than filling them with speculation.

## Expected Output
- An actor profile: aliases, suspected motivation, targeting, and a signature TTP
  set mapped to ATT&CK, each with citations and confidence.
- A relevance assessment to the organization with reasoning.
- Prioritized recommendations: techniques to emulate, detections to build/verify,
  and defensive gaps to close.
- A source list with dates and reliability grades.

## False Positives
- Over-attribution: assigning activity to an actor on weak or circular evidence.
- Conflating distinct groups that share tooling or an alias across vendors (naming
  differs between reporters).
- Treating outdated TTPs as current — actors evolve; note report dates.
- Assuming relevance without an actual targeting/sector match.

## Remediation
- Feed the signature TTPs into adversary emulation and detection-coverage
  validation to test real defenses against this actor.
- Prioritize detections and hardening for the actor's most-used, highest-impact
  techniques.
- Track the actor over time; refresh the profile as new reporting appears.
- Share the profile at the appropriate TLP with defenders and leadership.

## Reporting
```
Threat Actor Profiling
Purpose/Org context: <sector, geo, assets>   TLP: <level>
Actor: <name/aliases>   Suspected motivation: <...>   Confidence: <...>
Targeting: <sectors, regions, objectives, initial access>
Signature TTPs: technique (ATT&CK ID) | procedure/tooling | source | confidence
Relevance: <why this org; overlap with coverage>
Recommendations: emulation priorities, detections, hardening
Sources: <dated list with reliability grades>   Gaps: <known unknowns>
```

## References
- MITRE ATT&CK Groups: https://attack.mitre.org/groups/
- CISA Cybersecurity Advisories:
  https://www.cisa.gov/news-events/cybersecurity-advisories
- FIRST Cyber Threat Intelligence SIG: https://www.first.org/global/sigs/cti/
