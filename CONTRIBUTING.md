# Contributing

## Getting set up

```bash
npm ci
npm test          # unit tests; no network or Docker required
```

Integration tests need Docker:

```bash
npm run lab:up
npm run test:integration
npm run lab:down
```

Before opening a pull request, `npm run typecheck && npm run lint && npm test`
should be clean. CI runs the same on Node 20.11 and 22.

## Adding a check

Most contributions will be a new check. The shape is deliberately small.

**1. Decide whether the evidence already exists.** Look at `CollectorResultMap`
in [`src/types.ts`](src/types.ts). If what you need is already collected, you are
only writing a check — no new requests, no change to the request budget. Prefer
this.

**2. Write the check.** It is a pure function over evidence. It must not issue
requests; that is the collectors' job, and the separation is what keeps the
request count proportional to evidence rather than to check count.

```ts
export const exampleCheck: Check = {
  id: 'headers/example',              // category/name
  title: 'Human-readable name',
  category: 'headers',
  description: 'One line, shown by `parapet checks`.',
  requires: ['baseline'],             // collectors the engine must run first
  run(ctx) {
    const { response } = ctx.evidence('baseline');
    // ...
    return [];
  },
};
```

**3. Register it** in [`src/checks/index.ts`](src/checks/index.ts). Duplicate
ids throw at import rather than being discovered later.

**4. Test both directions.** A check that only has tests for the failing case is
half tested. Assert that it stays **quiet** on a correct configuration too —
that is where false positives live, and every false positive costs more trust
than the finding earns.

### What a good finding looks like

The bar is that a developer who has never seen the tool can act on it without
searching for anything.

- **`summary` states the consequence**, not the rule. Not "the `X-Frame-Options`
  header is missing" but what an attacker can do because it is missing.
- **`remediation` is specific enough to apply.** Name the directive, the config
  option, or the attribute. "Follow security best practices" is not remediation.
- **`severity` comes from [the rubric](docs/severity-rubric.md).** Where a
  modifier changes the impact — credentials on a CORS response, a session-shaped
  cookie name — compute severity in the check rather than fixing it per check.
- **`confidence` is honest.** If the check relies on a naming convention, it is
  `tentative`, and the summary should say so.
- **`references` point at a specification or a primary source.** RFC, MDN, OWASP.
- **Evidence carries no secrets.** Cookie values, `Authorization` headers and
  anything on the redaction list must not reach a report.

Finding ids are a public interface: `baseline` entries and SARIF fingerprints are
written against them. Changing one is a breaking change and belongs in the
changelog.

## Adding a collector

Only if a check genuinely needs evidence that does not exist yet. A collector
adds requests to every scan that uses it, so the cost is paid by all users.

Declare `dependsOn` accurately — the engine topologically sorts collectors and
uses that graph to decide what to skip when one fails. A collector should return
an empty-but-valid result rather than throwing when the target simply does not
have the thing (see `transport` on an `http` target).

## Scope

Things that will not be merged:

- Anything that sends a state-changing request. The `GET`/`OPTIONS` boundary in
  [SECURITY.md](SECURITY.md) is a promise to users, not a default.
- Exploitation, fuzzing, wordlists or credential testing. This audits
  configuration; it is not an attack tool.
- Checks that report on a status code alone. See the note in
  `src/evidence/collectors/exposure.ts` for why.
- CVSS scores. See [ADR 0005](docs/adr/0005-qualitative-severity.md).

## Reporting a vulnerability

Not through an issue — see [SECURITY.md](SECURITY.md).
