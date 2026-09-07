# parapet-scan

[![CI](https://github.com/sriharifortitude/parapet-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/parapet-scan/actions/workflows/ci.yml)

Audits the security posture a web application exposes to the internet — headers,
TLS, cookies, CORS, information disclosure and content integrity — and reports
what is wrong, why it matters, and how to fix it.

Runs as a CLI, as a Docker container, or as a CI gate that fails a build above a
severity you choose.

---

## The problem

Every team shipping a web application accumulates the same set of defects, and
almost nobody has a standing process that catches them:

- A `Content-Security-Policy` that contains `'unsafe-inline'` and therefore
  mitigates nothing.
- A CORS policy that reflects whatever `Origin` it is sent, with
  `Access-Control-Allow-Credentials: true` — every authenticated endpoint
  readable by any site a logged-in user visits.
- A session cookie without `HttpOnly`, or with `SameSite=None` and no `Secure`,
  which browsers silently discard.
- `/.git/` or `/.env` readable from the web root because a deployment copied the
  working directory.
- A certificate that expires on a Saturday.

None of these are hard to find. They dominate real penetration test reports
because nothing in a normal delivery pipeline looks for them, and a pentest
happens once a year.

This puts the check in the pipeline.

## What it looks like

Scanning the deliberately misconfigured target in [`lab/`](lab/):

```
$ parapet scan http://127.0.0.1:8080 --allow-private --quiet

http://127.0.0.1:8080/

  CRITICAL dotenv file is publicly readable
           disclosure/exposed-paths/dotenv-file (confirmed)
           http://127.0.0.1:8080/.env returned content matching a dotenv file.
           Environment files hold database credentials, API keys and signing secrets in
           plaintext. Treat every value in the retrieved file as compromised.
           Fix: Stop serving the file: deny the path at the web server, and exclude it from
           the deployment artefact so it is not present to be served. Then rotate every
           credential the file contained -- removing access does not undo the
           disclosure.

  HIGH     CORS allowlist can be bypassed by a lookalike origin
           cors/misconfiguration/allowlist-bypass (confirmed)
           The origin https://127.0.0.1.parapet-probe.invalid was accepted. It is not
           related to the target -- the match succeeded because the allowlist is
           comparing with a prefix, suffix or substring test rather than an exact
           comparison. Any domain the attacker registers can be shaped to pass the same
           test.
           Fix: Compare the Origin header against a fixed set of permitted origins with an
           exact string equality test. Never build the comparison out of startsWith,
           endsWith, includes or a regular expression with an unanchored hostname.

  ...

  16 requests in 1.5s

Summary
  1 critical  ·  7 high  ·  4 medium  ·  7 low  ·  5 info
```

Every finding names the weakness, states the consequence in terms of what an
attacker gains, and gives a remediation specific enough to act on. There is a
`--format html` report for sharing and `--format sarif` for GitHub code
scanning.

## Authorised use

**Only scan systems you own or have written permission to test.**

Every request the tool sends is a `GET` or an `OPTIONS`. It performs no writes,
no fuzzing, no brute-forcing, no exploitation and no credential testing, and it
talks only to the target you name. The full request inventory and the reasoning
behind those boundaries are in [SECURITY.md](SECURITY.md).

Sending unauthorised requests may still be unlawful regardless of how gentle
they are.

---

## What it checks

Nineteen checks in six categories. `parapet checks` lists them with ids.

| Category | Covers |
| --- | --- |
| **headers** | CSP (script sources, `unsafe-inline` vs nonce, wildcards, `base-uri`, `object-src`), HSTS (`max-age` grading, `includeSubDomains`), clickjacking via `frame-ancestors` **or** `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP |
| **cookies** | `Secure`, `HttpOnly`, `SameSite`, `__Host-`/`__Secure-` prefix rules, cookies scoped wider than the host |
| **cors** | Origin reflection, `null` origin, allowlist bypass by lookalike origin, preflight policy, wildcard-with-credentials |
| **tls** | Protocol versions negotiated in isolation, certificate expiry, self-signed, hostname coverage (RFC 6125 wildcard rules), key strength per algorithm, plaintext availability |
| **disclosure** | Version-bearing `Server`/`X-Powered-By` banners, publicly readable `.git`/`.env`/source maps, `security.txt` |
| **content** | Subresource integrity on third-party scripts, mixed content, forms posting over `http`, `rel=noopener` |

Some of the deliberate decisions behind that list:

- **Framing is one check across both mechanisms.** `frame-ancestors` supersedes
  `X-Frame-Options`, so reporting a missing `X-Frame-Options` on an origin that
  sets `frame-ancestors` would be a false positive.
- **`'unsafe-inline'` is not flagged when a nonce or hash is present.** Browsers
  ignore it in that case; flagging it would penalise a correctly built strict
  policy.
- **File exposure requires a content signature, not a `200`.** Single-page apps
  answer every unknown path with their index document. Status-based detection
  turns into a false-positive generator on exactly the stacks this gets pointed
  at most.
- **Missing `rel=noopener` is `info`, not `low`.** Browsers have implied it since
  2021. Calling it exploitable on a current client would be inflation.

## Severity

Findings carry a qualitative severity and a **separate** confidence level. There
is no CVSS score, deliberately: this tool observes a configuration from outside
and does not know what data sits behind it, so a computed vector would assert a
precision the evidence cannot support.

The full rubric, with the reasoning, is in
[docs/severity-rubric.md](docs/severity-rubric.md); the decision is recorded in
[ADR 0005](docs/adr/0005-qualitative-severity.md).

---

## Architecture

```
                 ┌──────────────┐
   target  ──►   │  scope guard │  resolve, screen reserved ranges, reject
                 └──────┬───────┘  non-http schemes and embedded credentials
                        │
                 ┌──────▼───────┐
                 │ HTTP client  │  rate-limited, manual redirects,
                 └──────┬───────┘  capped body reads, request budget
                        │
                 ┌──────▼───────┐
                 │  collectors  │  baseline · transport · tls · document
                 └──────┬───────┘  cors · well-known · exposure
                        │
                   evidence (typed, fetched once, shared)
                        │
                 ┌──────▼───────┐
                 │    checks    │  pure functions, issue no requests
                 └──────┬───────┘
                        │
                   findings ──► redaction ──► terminal │ json │ sarif │ html
```

The load-bearing decision is the split between **collectors**, which issue
requests, and **checks**, which are pure functions over the evidence and issue
none. Checks declare what they need; the engine computes the transitive closure,
runs each collector once, and skips checks whose evidence is unavailable.

That gives three things:

1. **Request count is proportional to evidence, not to check count.** A full
   scan is ~16 requests for 19 checks. Adding a twentieth header check adds
   zero. This is what makes it safe to point at production.
2. **Checks are trivially testable.** No HTTP, no mocking — construct evidence,
   assert on findings. It is why there are 117 unit tests.
3. **Failure is legible.** A failed TLS handshake marks the two TLS checks
   *skipped* and runs the other seventeen. The report distinguishes "checked and
   clean" from "could not check".

The trade-offs are written up in
[ADR 0002](docs/adr/0002-evidence-separate-from-checks.md).

### Project structure

```
src/
  core/         scope guard, HTTP client, engine, CSP and Set-Cookie parsers,
                severity rubric
  evidence/     collectors — the only code that issues requests
  checks/       one module per concern, grouped by category
  reporting/    terminal, json, sarif, html, and central redaction
  config/       zod schema and layered file/CLI resolution
  cli/          commander wiring
lab/            deliberately misconfigured target for the integration tests
tests/          117 unit, 32 integration
docs/adr/       decision records
```

### Why TypeScript for a security tool

Security tooling defaults to Python. The dominant input here is untrusted remote
data — headers that may be absent, duplicated, malformed or hostile — which is
exactly what a strict type system catches at the boundary.
`noUncheckedIndexedAccess` forces every `split()[1]` to be handled rather than
assumed, and a meaningful share of the parser bugs in this codebase were caught
by the compiler before a test existed.

The cost is real and stated: there is no equivalent of `cryptography` or
`scapy`, so anything below the TLS handshake — cipher suite enumeration, chain
path building — is out of scope rather than half-implemented. See
[ADR 0001](docs/adr/0001-typescript-for-a-security-tool.md).

---

## Installation

Requires Node 20.11 or later.

Not yet published to npm, so install from source or use the Docker image:

```bash
git clone https://github.com/sriharifortitude/parapet-scan.git
cd parapet-scan
npm ci
npm run build
node dist/cli/index.js scan https://example.com

# Optional: put `parapet` on your PATH, which is what the examples below assume
npm link
```

With Docker, if you would rather not have Node on the machine:

```bash
docker build -t parapet-scan .
docker run --rm parapet-scan scan https://example.com

# Write a report out to the current directory
docker run --rm -v "$PWD:/out" parapet-scan \
  scan https://example.com --format html --output /out/report.html
```

The image is a two-stage build that discards the toolchain and runs as the
unprivileged `node` user.

## Usage

```bash
# Scan, hiding info-level hardening notes
parapet scan https://example.com --quiet

# Show the evidence behind each finding
parapet scan https://example.com --evidence

# Headers and cookies only
parapet scan https://example.com --category headers cookies

# Authenticated scan (cookies set after login are invisible to an anonymous one)
parapet scan https://example.com --header "Authorization: Bearer $TOKEN"

# Shareable HTML report
parapet scan https://example.com --format html --output report.html

# List the checks
parapet checks
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; nothing at or above the threshold |
| `1` | Scan completed; findings at or above `--fail-on` (default `high`) |
| `2` | The scan could not be completed |

Keeping "found problems" separate from "could not run" is what stops a
misconfigured pipeline from reading as a clean bill of health.

## Configuration

Copy [`parapet.example.yml`](parapet.example.yml) to `parapet.yml`. Every key is
optional and documented in that file. CLI flags override it.

Unknown keys are **rejected**, not ignored — a typo in a security setting that
silently does nothing is worse than a failed startup.

The `baseline` list holds accepted risk. Findings on it are still evaluated and
still appear in the report under `suppressed`, but do not count toward
`--fail-on`. It takes *finding* ids (`headers/csp/missing`), not *check* ids, so
accepting one finding does not silence a whole check.

## Running in CI

```yaml
- name: Security posture scan
  run: |
    docker run --rm ghcr.io/sriharifortitude/parapet-scan:latest       scan https://staging.example.com --fail-on high
```

Or upload SARIF so findings appear in the GitHub Security tab:

```yaml
- run: |
    docker run --rm -v "$PWD:/out" ghcr.io/sriharifortitude/parapet-scan:latest       scan https://staging.example.com --format sarif --output /out/parapet.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: parapet.sarif
```

The image is not published yet either — build it locally with
`docker build -t parapet-scan .` and use that tag until it is.

Results carry a stable `partialFingerprints` value so code scanning tracks a
finding across runs instead of reporting it as new each time.

On an existing application, set `failOn: high` and put the current medium and
low findings in `baseline`, then empty it over time. Starting at `medium`
usually means the first run fails and the gate gets disabled.

## Development

```bash
npm run typecheck
npm run lint
npm test                 # 117 unit tests, no network or Docker needed

npm run lab:up           # start the deliberately misconfigured target
npm run test:integration # 32 tests driving the real engine over real HTTP
npm run lab:down
```

### Testing approach

Unit tests cover the parsers and every check as a pure function over constructed
evidence, including the cases where a check must stay **quiet** — a nonce
alongside `'unsafe-inline'`, `frame-ancestors` without `X-Frame-Options`, a
256-bit EC key.

Integration tests run the real engine over real HTTP against the container in
`lab/`. Nothing is mocked. The lab's 404 handler returns a styled body with a
`200` status on purpose, so the file-exposure signatures are tested against the
case they exist to survive, and a `/hardened` endpoint verifies the checks go
silent when the configuration is correct.

## Limitations

Worth knowing before you rely on this:

- **It sees served HTML only.** Anything a client-side framework injects after
  hydration is invisible. There is no headless browser.
- **It scans one URL per target, not a site.** No crawling. A weakness on a page
  you do not name will not be found.
- **Cookies are only those set on the scanned response.** A session cookie
  issued after login needs an authenticated scan (`--header`).
- **No cipher suite enumeration.** Protocol versions are probed; individual
  cipher suites are not. See [ADR 0001](docs/adr/0001-typescript-for-a-security-tool.md).
- **The scope guard screens addresses at resolution time.** DNS rebinding
  between the check and the request is not defended against; the gap and what
  closing it would take are documented in
  [ADR 0003](docs/adr/0003-scope-guard.md).
- **A WAF changes the answer.** If one blocks the CORS probes, the CORS results
  describe the WAF rather than the application.
- **It is not a penetration test.** It finds configuration weaknesses. It does
  not find business logic flaws, injection, or broken access control.

## Possible next steps

Not promises — the directions that would add the most, in order:

- Pin the resolved address into the connection, closing the rebinding gap in
  ADR 0003.
- Multi-page scanning from a supplied URL list, so a whole application can be
  covered without a crawler.
- A published GitHub Action wrapper, so CI use does not need a `run` step.
- Diff mode: compare two JSON reports and fail only on findings that are new,
  which suits a team that has a backlog it is working down.

## License

MIT. See [LICENSE](LICENSE).
