import type { Check, Evidence, FindingInput } from '../../types.js';

/** Headers whose only purpose is to name the software, and often its version. */
const BANNER_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
] as const;

/** A version number is the part that turns a banner into a lookup key for known CVEs. */
const VERSIONED = /\d+\.\d+/;

const REFERENCE = {
  title: 'OWASP WSTG: Fingerprint Web Server',
  url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
};

/**
 * Banner disclosure is not a vulnerability and is reported at info or low
 * accordingly. It is included because it is cheap to fix and because a
 * version-bearing banner is what lets an untargeted scan decide this host is
 * worth a second look.
 */
export const serverBannerCheck: Check = {
  id: 'disclosure/server-banner',
  title: 'Software version disclosure',
  category: 'disclosure',
  description: 'Reports response headers that name the server software or its version.',
  requires: ['baseline'],

  run(ctx) {
    const { response } = ctx.evidence('baseline');
    const disclosed: Evidence[] = [];
    let versioned = false;

    for (const name of BANNER_HEADERS) {
      const value = response.headers.get(name);
      if (value === undefined || value.trim() === '') continue;
      disclosed.push({ kind: 'header', name, value });
      if (VERSIONED.test(value)) versioned = true;
    }

    const generator = ctx.tryEvidence('document')?.generatorMeta;
    if (generator !== undefined) {
      disclosed.push({ kind: 'markup', snippet: `<meta name="generator" content="${generator}">` });
      if (VERSIONED.test(generator)) versioned = true;
    }

    if (disclosed.length === 0) return [];

    const finding: FindingInput = {
      id: versioned
        ? 'disclosure/server-banner/versioned'
        : 'disclosure/server-banner/present',
      title: versioned
        ? 'Response headers disclose software versions'
        : 'Response headers name the server software',
      severity: versioned ? 'low' : 'info',
      confidence: 'confirmed',
      summary: versioned
        ? 'The responses carry exact version numbers. That is enough to match the host against ' +
          'published advisories for those versions without sending a single additional request, ' +
          'which is how opportunistic scanning selects targets.'
        : 'The responses name the server software. On its own this is low value to an ' +
          'attacker, but it narrows the set of techniques worth trying.',
      evidence: disclosed,
      remediation: versioned
        ? 'Suppress the version component at the server or proxy: server_tokens off in nginx, ' +
          'ServerTokens Prod in Apache, and remove X-Powered-By at the application layer. This ' +
          'is a delay, not a defence -- patching remains the control that matters.'
        : 'Remove or genericise these headers if there is no operational reason to keep them.',
      references: [REFERENCE],
    };

    return [finding];
  },
};
