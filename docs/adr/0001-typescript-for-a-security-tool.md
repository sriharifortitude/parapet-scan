# 0001. TypeScript rather than Python

**Status:** accepted

## Context

Security tooling defaults to Python. `sslyze`, `testssl.sh`, most of the OWASP
tooling and nearly every scanner an engineer would reach for lives there, and
the ecosystem for protocol work is deeper.

## Decision

Build in TypeScript on Node, with `strict`, `exactOptionalPropertyTypes` and
`noUncheckedIndexedAccess` enabled.

## Reasoning

The dominant input to this program is untrusted remote data: headers that may be
absent, duplicated, malformed or hostile. That is precisely the class of bug a
strict type system catches at the boundary. `noUncheckedIndexedAccess` in
particular forces every `headers[0]` and `split()[1]` to be handled rather than
assumed, and a large share of parser bugs in this codebase were caught by the
compiler before a test existed.

`undici` gives low-level control over redirects, connection reuse and body
limits, all of which the design depends on. Node's `tls` module exposes the
handshake and peer certificate directly, which is the only platform requirement
the TLS collector has.

There is also a practical reason. A JSON contract shared with a TypeScript
consumer keeps a single set of types across the tool and anything that reads its
output, which is the intended relationship with the reporting UI this project is
meant to feed.

## Costs

- No equivalent of `cryptography` or `scapy`. Anything below the TLS handshake —
  cipher suite enumeration, certificate chain path building — would mean binding
  to OpenSSL rather than using a library. Cipher enumeration is out of scope for
  this reason, and that is stated in the README rather than half-implemented.
- Fewer prior implementations to compare against when a protocol detail is
  ambiguous.

## Alternatives rejected

**Python.** Better protocol libraries, worse guarantees at the parsing boundary,
and it would not share types with any consumer of the output.

**Go.** Excellent for this, and a single static binary is a real distribution
advantage. Rejected because the type-level guarantees around optionality are
weaker than TypeScript's, and `npx` distribution matters more than a binary for
a tool whose main deployment target is a CI job that already has Node.
