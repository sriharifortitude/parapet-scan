# 0004. Inspect TLS without certificate verification

**Status:** accepted

## Context

The TLS collector opens connections with `rejectUnauthorized: false`. In almost
any other codebase that is a defect, and a reviewer — or a linter — is right to
stop on it.

## Decision

Keep it, confined to the TLS collector, and document why here and at the call
site.

## Reasoning

The collector's job is to **describe** the certificate a server presents. The
findings that matter most are the invalid ones: expired, self-signed, hostname
mismatched. Those are exactly the certificates a verifying client refuses to
complete a handshake with.

With verification on, the collector would fail to connect and report nothing
precisely when it has the most to say — an expired certificate would surface as
"handshake failed" rather than "this certificate expired nine days ago". The
tool would be silent in the cases it exists for. Every TLS auditing tool —
`sslyze`, `testssl.sh`, SSL Labs — makes the same choice for the same reason.

The reason this is safe here is that **nothing is trusted over these sockets**.
They carry a handshake, the peer certificate and negotiated parameters are read,
and the socket is destroyed. No request is sent, no response body is parsed, no
credential is transmitted. The threat that certificate verification defends
against — an interceptor substituting content or capturing secrets — has no
surface, because there is no content and no secret.

The ordinary HTTP client, which *does* send headers and parse bodies, keeps
verification enabled.

## Costs

- The distinction has to be understood to review the file safely. That is what
  this record and the comment on `INSPECTION_ONLY` are for.
- Static analysis flags it. That is the correct behaviour from the analyser; the
  finding is accepted here with a written reason rather than suppressed silently.

## Alternatives rejected

**Verify, and infer the problem from the failure message.** OpenSSL error
strings are the only evidence available, they vary by version, and the result is
a worse finding — no expiry date, no issuer, no subject alternative names.

**Two handshakes: one verifying to get a pass/fail, one not, to get the
details.** Doubles the connections for information already derivable from the
certificate the second handshake returns.
