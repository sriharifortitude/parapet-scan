# 0005. Qualitative severity instead of CVSS

**Status:** accepted

## Context

Reports are more credible with numbers on them, and clients ask for CVSS because
their tracking systems have a field for it.

## Decision

Assign one of five qualitative severities from the rubric in
[../severity-rubric.md](../severity-rubric.md), paired with a separate
confidence level. Emit no CVSS vector and no numeric score.

## Reasoning

CVSS requires inputs this tool does not have. Attack complexity, privileges
required, user interaction and scope all depend on the application behind the
configuration. A missing CSP on a static marketing page and a missing CSP on an
authenticated banking application produce identical observations and very
different real scores.

A tool that emits `7.4` from those unknowns is not measuring — it is generating
a number that looks like a measurement. Reviewers who know CVSS spot invented
vectors quickly, and it costs the credibility of the findings that *are* solid.

Separating severity from confidence also makes triage better than a single score
does. "Medium severity, tentative confidence" tells a reader exactly how to
spend their time. A 5.3 does not.

## Costs

- Findings cannot be dropped straight into a system that requires a CVSS score.
- Comparing output against a scanner that does emit CVSS requires a mapping.
- "Why is this medium?" is answered by a document rather than an arithmetic
  formula, so the rubric has to actually be maintained.

## Alternatives rejected

**Emit CVSS with worst-case assumptions.** Every finding inflates to the top of
its plausible range, which is how scanner output ends up ignored.

**Let the user supply the missing context in config.** Plausible, and a real
option later. Rejected for now because it asks the operator to answer questions
about their own application before the first scan, which is the wrong place to
put friction.
