# 0003. Resolve and screen targets before the first request

**Status:** accepted

## Context

The scanner takes a hostname from a CLI argument or a config file. The config
file may itself be populated from a CI variable. It then issues HTTP requests
from wherever it runs — frequently a build agent inside a private network, or a
container in a cloud VPC where `169.254.169.254` serves instance credentials.

Described that way, this program is a server-side request forgery primitive with
a command-line interface.

## Decision

Before any request is sent, `assertTargetInScope` resolves the hostname and
screens every returned address against reserved IPv4 and IPv6 ranges. A target
that resolves into one is rejected. `--allow-private` is the explicit opt-out,
and it exists mainly so the bundled lab can be scanned.

The URL is also rejected if it carries a non-`http(s)` scheme or embedded
credentials.

## Reasoning

The dangerous case is not someone typing `127.0.0.1`. It is a `parapet.yml`
committed to a repository, or a target passed through a pipeline variable, that
resolves somewhere the operator did not intend. Screening resolved addresses
rather than the literal string is what catches a hostname with an `A` record
pointing at link-local space.

IPv6 is screened as thoroughly as IPv4, including IPv4-mapped forms, because
`::ffff:169.254.169.254` otherwise walks straight past a v4-only check.

Unparseable input is treated as reserved rather than allowed. Failing closed on
a case the parser does not understand is the correct default for a guard.

## Known limitation

This screens the addresses seen **at resolution time**. A DNS record that
changes between the check and the request — a rebinding attack — is not defended
against. Closing that gap means pinning the resolved address into the connection
so the socket cannot reach a different host than the one screened, which
requires a custom `undici` connector.

That is a real gap and it is documented rather than glossed over. It is not
currently closed because the threat model is an operator scanning their own
infrastructure, where the adversary controlling DNS for the target is already in
a stronger position than the scan would give them. It would need to be closed
before this ran as a hosted service accepting targets from untrusted users.

## Costs

- One resolution before the scan, and a second implicit one when the request is
  made.
- Scanning a host on your own network requires a flag, which is mild friction
  for the most common development case.
