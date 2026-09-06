import {
  isScopeWiderThanHost,
  looksSessionBearing,
  parseSetCookie,
  prefixRequirementViolation,
  type ParsedCookie,
} from '../../core/cookies.js';
import type { Check, Evidence, FindingInput, Severity } from '../../types.js';

const REFERENCE = {
  title: 'OWASP Session Management Cheat Sheet',
  url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
};
const RFC = {
  title: 'RFC 6265bis: Cookies',
  url: 'https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis',
};

/**
 * Only cookies set on this one response are visible. A cookie issued after
 * login will not appear in an unauthenticated scan, which is the main reason
 * the README recommends running authenticated scans with --header for anything
 * beyond a first pass.
 */
export const cookieAttributesCheck: Check = {
  id: 'cookies/attributes',
  title: 'Cookie attributes',
  category: 'cookies',
  description: 'Inspects Set-Cookie attributes on the scanned response.',
  requires: ['baseline'],

  run(ctx) {
    const { response } = ctx.evidence('baseline');
    const findings: FindingInput[] = [];

    for (const raw of response.headers.getAll('set-cookie')) {
      const cookie = parseSetCookie(raw);
      if (cookie === undefined) continue;

      // Only the attributes are evidence; the value may be a live session token.
      const evidence: Evidence[] = [
        { kind: 'header', name: 'set-cookie', value: redactValue(cookie) },
      ];
      const sensitive = looksSessionBearing(cookie);

      if (ctx.target.isHttps && !cookie.secure) {
        findings.push({
          id: `cookies/attributes/no-secure:${cookie.name}`,
          title: `Cookie "${cookie.name}" is not marked Secure`,
          severity: escalate('medium', sensitive),
          confidence: 'confirmed',
          summary:
            'The cookie is sent on plaintext requests as well as https ones. Any request to ' +
            'the http form of this host -- a typed address, an old bookmark, an injected ' +
            'image reference -- discloses it to anyone on the network path.',
          evidence,
          remediation: 'Add the Secure attribute to every cookie set over https.',
          references: [REFERENCE],
        });
      }

      if (!cookie.httpOnly) {
        findings.push({
          id: `cookies/attributes/no-httponly:${cookie.name}`,
          title: `Cookie "${cookie.name}" is readable from JavaScript`,
          severity: sensitive ? 'medium' : 'info',
          confidence: sensitive ? 'firm' : 'tentative',
          summary: sensitive
            ? 'The name suggests this cookie carries session or authentication state, and ' +
              'without HttpOnly any script running on the page -- including injected script -- ' +
              'can read and exfiltrate it.'
            : 'The cookie is readable by document.cookie. This is expected for cookies the ' +
              'front end has to read, and worth removing otherwise.',
          evidence,
          remediation: sensitive
            ? 'Add HttpOnly. Session cookies should never need to be read from script.'
            : 'Add HttpOnly unless client-side code genuinely reads this cookie.',
          references: [REFERENCE],
        });
      }

      if (cookie.sameSite === undefined) {
        findings.push({
          id: `cookies/attributes/no-samesite:${cookie.name}`,
          title: `Cookie "${cookie.name}" has no SameSite attribute`,
          severity: sensitive ? 'low' : 'info',
          confidence: 'firm',
          summary:
            'Current browsers default to Lax, but the default is not uniform across clients ' +
            'and is not guaranteed. Stating the intent explicitly is what makes the ' +
            'cross-site behaviour of the cookie reviewable.',
          evidence,
          remediation:
            'Set SameSite=Lax for session cookies, or Strict where no cross-site navigation ' +
            'needs to carry the session.',
          references: [RFC],
        });
      } else if (cookie.sameSite === 'none' && !cookie.secure) {
        findings.push({
          id: `cookies/attributes/samesite-none-insecure:${cookie.name}`,
          title: `Cookie "${cookie.name}" uses SameSite=None without Secure`,
          severity: 'medium',
          confidence: 'confirmed',
          summary:
            'SameSite=None requires Secure. Browsers reject the cookie outright, so it is ' +
            'not being stored at all -- this usually shows up as an intermittent session bug ' +
            'before it is recognised as a configuration error.',
          evidence,
          remediation: 'Add Secure, or drop to SameSite=Lax if cross-site sending is not needed.',
          references: [RFC],
        });
      }

      const prefixIssue = prefixRequirementViolation(cookie);
      if (prefixIssue !== undefined) {
        findings.push({
          id: `cookies/attributes/prefix-violation:${cookie.name}`,
          title: `Cookie "${cookie.name}" does not satisfy its name prefix`,
          severity: 'medium',
          confidence: 'confirmed',
          summary:
            `${prefixIssue}. The browser enforces prefix requirements and will refuse the ` +
            'cookie, so the integrity guarantee the prefix is there to provide is absent and ' +
            'the cookie itself is discarded.',
          evidence,
          remediation: 'Either satisfy the prefix requirements or remove the prefix from the name.',
          references: [RFC],
        });
      }

      if (isScopeWiderThanHost(cookie, ctx.target.hostname)) {
        findings.push({
          id: `cookies/attributes/broad-domain:${cookie.name}`,
          title: `Cookie "${cookie.name}" is scoped to ${cookie.domain}`,
          severity: sensitive ? 'low' : 'info',
          confidence: 'firm',
          summary:
            `The cookie is sent to every host under ${cookie.domain}, not just ` +
            `${ctx.target.hostname}. Any subdomain -- including one run by a third party or ` +
            'left over from a retired service -- receives it on every request.',
          evidence,
          remediation:
            'Drop the Domain attribute so the cookie stays host-only, unless sibling ' +
            'subdomains genuinely need it.',
          references: [REFERENCE],
        });
      }
    }

    return findings;
  },
};

function escalate(base: Severity, sensitive: boolean): Severity {
  if (!sensitive) return base;
  return base === 'medium' ? 'high' : base;
}

/** Reports must be shareable, so the cookie value never leaves the scanner. */
function redactValue(cookie: ParsedCookie): string {
  const attributes = cookie.raw.slice(cookie.raw.indexOf(';'));
  const suffix = cookie.raw.includes(';') ? attributes : '';
  return `${cookie.name}=<redacted, ${cookie.value.length} chars>${suffix}`;
}
