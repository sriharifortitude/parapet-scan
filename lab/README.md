# Lab target

A small HTTP server that is misconfigured on purpose, so the scanner can be
tested against real responses instead of mocked ones.

Every finding the integration suite asserts is produced by this server. That
makes the tests meaningful — they exercise the HTTP client, the collectors and
the checks together — and it means the project never needs to point at a
third-party site to demonstrate that it works.

## Running it

```
npm run lab:up
npx bastion scan http://127.0.0.1:8080 --allow-private
npm run lab:down
```

`--allow-private` is required because the scope guard rejects targets that
resolve to reserved address ranges unless you say otherwise.

## What is wrong with it, deliberately

`/` omits every security header, reflects any `Origin` with
`Access-Control-Allow-Credentials: true`, sets cookies with no `Secure`,
`HttpOnly` or `SameSite` attributes, sets a `__Host-` prefixed cookie that
violates the prefix rules, advertises versioned `Server` and `X-Powered-By`
banners, loads a cross-origin script with no integrity attribute, references a
stylesheet over plaintext, and posts a password field to an `http://` URL.

`/.git/HEAD`, `/.git/config`, `/.env` and `/static/app.js.map` are served from
the web root. The `.env` contents are fabricated placeholders.

Unknown paths return a styled 404 body with a **200** status. That is there on
purpose: it is the pattern that makes status-code-based path detection produce
false positives, and it is what the exposure collector's content signatures are
tested against.

`/hardened` serves the headers `/` omits, so the tests can also assert that
checks stay quiet when a configuration is correct.

## Constraints

The container runs read-only, drops all capabilities, sets
`no-new-privileges`, and publishes only to `127.0.0.1`. It stores nothing and
has no dependencies beyond the Node base image.

**Do not deploy this anywhere reachable.** It is a test fixture.
