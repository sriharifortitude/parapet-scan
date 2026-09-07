# Architecture decision records

Short notes on decisions that were not obvious, written at the time they were
made. Each records what was chosen, what was rejected, and what it costs.

They exist because the reasoning behind a design is the part that gets lost
first, and because "why is TLS verification disabled here?" is a question this
codebase should answer before a reviewer has to ask it.

| # | Decision |
| --- | --- |
| [0001](0001-typescript-for-a-security-tool.md) | TypeScript rather than Python |
| [0002](0002-evidence-separate-from-checks.md) | Evidence collection separated from checks |
| [0003](0003-scope-guard.md) | Resolve and screen targets before the first request |
| [0004](0004-tls-inspection-without-verification.md) | Inspect TLS without certificate verification |
| [0005](0005-qualitative-severity.md) | Qualitative severity instead of CVSS |
