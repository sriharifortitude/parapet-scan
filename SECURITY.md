# Security policy

## Authorised use only

Only scan systems you own or have written permission to test.

Sending requests to a system you are not authorised to test may be unlawful
regardless of intent or impact — in the UK under the Computer Misuse Act 1990,
in the US under the CFAA, and under equivalent legislation elsewhere. "It was
only a GET request" is not a defence, and neither is "the tool is read-only".

If you are testing on behalf of a client, get the authorisation in writing,
including the in-scope hostnames and a time window, before the first scan.

## What this tool does to a target

Every request is a `GET` or an `OPTIONS`. Specifically, a full scan of one
target sends:

- one request for the target document, following redirects
- one request to the `http://` form of an `https` target, to check for an upgrade
- four requests carrying different `Origin` headers, to observe the CORS policy
- two requests for `/robots.txt` and `/.well-known/security.txt`
- seven requests for a **fixed** list of paths that should never be readable
  (`/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/.DS_Store`,
  `/server-status`, `/phpinfo.php`)
- up to three requests for source maps referenced by the page's own scripts
- up to five TLS handshakes, which are closed without sending a request

Roughly 16–20 requests, rate-limited, with a hard ceiling (`maxRequests`,
default 80) that aborts the scan rather than exceeding it.

## What it deliberately does not do

- **No writes.** It never sends `POST`, `PUT`, `PATCH` or `DELETE`.
- **No fuzzing or brute-forcing.** The path list is fixed and short. It does not
  use a wordlist, does not recurse, and does not guess application routes.
- **No exploitation.** It observes configuration. It does not send injection
  payloads, does not attempt to retrieve data through a weakness it finds, and
  does not verify a finding by exploiting it.
- **No credential testing.** It never attempts a login and has no password list.
- **No third-party requests.** It talks only to the target you name. The
  `.invalid` origins used in the CORS probes are reserved by RFC 2606 and are
  never resolved or contacted.
- **No telemetry.** It phones nothing home and stores nothing outside the report
  you asked for.

## Handling of secrets

- The scope guard rejects URLs with embedded credentials, so they cannot end up
  in a report or in shell history. Pass authentication with `--header` instead.
- Header values on the redaction list — `authorization`, `cookie`, `set-cookie`,
  `proxy-authorization`, `x-api-key` by default — are replaced before any
  reporter sees a finding. Extend the list with `redactHeaders` in the config.
- Cookie **values** are never included in evidence, only names and attributes.
- Reports can still contain excerpts of whatever the target served. If a `.env`
  file was exposed, the excerpt of it is the evidence. **Treat generated reports
  as sensitive**, and note that `.gitignore` excludes the default report
  filenames for that reason.

## Running it safely against production

- Start with `--no-probe-paths` if you want the header, TLS, cookie and CORS
  analysis without any request for a file that does not exist.
- Keep the default concurrency of 4 and the 100 ms inter-request delay. They
  exist so the scan does not resemble an attack in the target's own logs.
- Tell whoever watches the logs before you run it. A WAF that blocks the CORS
  probes will make the results wrong as well as causing alerts.

## The lab

`lab/` contains a deliberately misconfigured server used by the integration
tests. It is a test fixture: it binds to loopback, runs read-only with all
capabilities dropped, and the credentials it serves are fabricated placeholders.

**Do not deploy it anywhere reachable.**

## Reporting a vulnerability in this tool

Open a [security advisory](https://github.com/sriharifortitude/parapet-scan/security/advisories/new)
rather than a public issue.

Please include the version, what you did, what happened, and what you expected.
An initial response should be expected within a week.

The issues most worth reporting here: a way to make the scanner send a request
outside its documented boundary; a way to bypass the scope guard; anything that
places a secret into report output; a crafted response that causes resource
exhaustion in the scanner.
