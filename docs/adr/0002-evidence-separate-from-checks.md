# 0002. Evidence collection separated from checks

**Status:** accepted

## Context

The obvious design is for each check to fetch what it needs. It is simpler to
write, and each check is self-contained.

With nineteen checks it also means up to nineteen requests to render one
verdict, mostly for the same document.

## Decision

Split into **collectors**, which issue requests and return typed evidence, and
**checks**, which are pure functions over that evidence and issue no requests at
all. Checks declare the collectors they need in `requires`; the engine computes
the transitive closure, orders it, runs each collector once, and only runs a
check whose evidence is present.

## Reasoning

**Request count becomes proportional to the evidence needed, not to the number
of checks.** A full scan of the lab is 16 requests for 19 checks, and adding a
twentieth header check adds zero. That is the difference between an audit and
load, and it is what makes the tool safe to point at a production origin.

**Checks become trivially testable.** A check is a pure function, so a test
constructs the evidence and asserts on the findings — no HTTP, no mocking a
client, no fixtures. This is why there are 117 unit tests: they were cheap.

**Failures are contained and legible.** When the TLS handshake fails, the engine
records the collector error, marks the two TLS checks as skipped, and runs the
other seventeen. The report distinguishes "checked and clean" from "could not
check", which a design where each check fetches its own data cannot do without
each check reimplementing it.

## Costs

- A check cannot ask a follow-up question. If a header's value suggests a second
  request would be informative, the check cannot make it — the collector has
  already returned. So far this has cost nothing, but a check that needs
  adaptive probing would require a new collector rather than a small edit.
- The evidence types are a shared surface. Adding a field means touching the
  type, the collector and the tests together.
- The dependency graph needs ordering and cycle detection, which is machinery a
  self-contained check would not need.

## Alternatives rejected

**A shared response cache behind a normal HTTP client.** Gets the request count
down without the structural split. Rejected because it makes request behaviour
implicit — whether a check costs a request depends on what ran before it — and
because it does not give the engine the information it needs to report a check
as skipped rather than clean.
