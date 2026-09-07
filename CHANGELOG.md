# Changelog

Notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

Finding ids are part of the public interface — they are what `baseline` and
`--disable` are written against, and what SARIF fingerprints are built from. A
finding id that changes meaning or disappears is a breaking change and is called
out as such.

## [Unreleased]

## [0.1.0] - 2026-09-07

First release.

### Added

- Scan engine that separates evidence collection from checks, so a full scan of
  one target costs roughly 16 requests regardless of how many checks run.
- Seven evidence collectors: baseline document, plaintext transport probe, TLS
  handshake and certificate, parsed DOM, CORS probes, `well-known` paths, and a
  fixed list of commonly exposed files.
- Nineteen checks across headers, cookies, CORS, TLS, information disclosure and
  content integrity.
- Scope guard that resolves the target and rejects reserved IPv4 and IPv6
  ranges, non-`http(s)` schemes and URLs carrying embedded credentials.
  `--allow-private` is the documented opt-out.
- Rate-limited HTTP client with manual redirect handling, capped body reads and
  a hard request budget.
- Four report formats: terminal, JSON, SARIF 2.1.0 with stable fingerprints, and
  a self-contained HTML file.
- Central redaction of sensitive header values before any reporter runs; cookie
  values are never placed in evidence.
- YAML configuration with a strict schema that rejects unknown keys, plus a
  `baseline` list for accepted risk that keeps suppressed findings visible in
  the report.
- Docker image, and a CI workflow covering Node 20.11 and 22.
- A deliberately misconfigured lab target used by the integration tests.
- Decision records for the five choices most likely to be questioned in review.

[Unreleased]: https://github.com/sriharifortitude/parapet-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sriharifortitude/parapet-scan/releases/tag/v0.1.0
