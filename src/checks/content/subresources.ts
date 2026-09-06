import type { Check, Evidence, FindingInput } from '../../types.js';

const SRI_REFERENCE = {
  title: 'MDN: Subresource Integrity',
  url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
};

export const subresourceIntegrityCheck: Check = {
  id: 'content/subresource-integrity',
  title: 'Subresource integrity',
  category: 'content',
  description: 'Finds third-party scripts and stylesheets loaded without an integrity hash.',
  requires: ['document'],

  run(ctx) {
    const document = ctx.evidence('document');
    if (!document.isHtml) return [];

    const unprotected = [...document.scripts, ...document.stylesheets].filter(
      (element) => element.isCrossOrigin && element.integrity === undefined,
    );
    if (unprotected.length === 0) return [];

    const evidence: Evidence[] = unprotected.slice(0, 10).map((element) => ({
      kind: 'markup',
      snippet: `<script src="${element.src}">`,
      location: new URL(element.src).origin,
    }));
    if (unprotected.length > evidence.length) {
      evidence.push({
        kind: 'note',
        text: `${unprotected.length - evidence.length} further subresources omitted.`,
      });
    }

    const origins = [...new Set(unprotected.map((element) => originOf(element.src)))];

    return [
      {
        id: 'content/subresource-integrity/missing',
        title: `${unprotected.length} third-party subresource${unprotected.length === 1 ? '' : 's'} loaded without integrity`,
        severity: 'low',
        confidence: 'firm',
        summary:
          `The page loads code from ${origins.length} external origin${origins.length === 1 ? '' : 's'} ` +
          `(${origins.slice(0, 3).join(', ')}${origins.length > 3 ? ', ...' : ''}) with no ` +
          'integrity attribute. Whoever controls those origins -- or anyone who compromises ' +
          'them -- can change the delivered code and it will execute with full access to this ' +
          'page. This is the mechanism behind CDN supply-chain incidents.',
        evidence,
        remediation:
          'Add integrity and crossorigin attributes to each pinned third-party resource, or ' +
          'self-host the file so it is covered by your own deployment pipeline. Note that SRI ' +
          'requires a fixed URL: it cannot be used with a rolling "latest" endpoint.',
        references: [SRI_REFERENCE],
      } satisfies FindingInput,
    ];
  },
};

export const mixedContentCheck: Check = {
  id: 'content/mixed-content',
  title: 'Mixed content',
  category: 'content',
  description: 'Finds plaintext subresources referenced from an https document.',
  requires: ['document'],

  run(ctx) {
    const document = ctx.evidence('document');
    if (!document.isHtml || document.insecureSubresources.length === 0) return [];

    return [
      {
        id: 'content/mixed-content/insecure-subresource',
        title: `${document.insecureSubresources.length} subresource${document.insecureSubresources.length === 1 ? '' : 's'} referenced over http`,
        severity: 'medium',
        confidence: 'confirmed',
        summary:
          'An https document references resources over plaintext http. Browsers block active ' +
          'mixed content such as script outright, which breaks the feature that depends on it, ' +
          'and upgrade or block passive content depending on version. Where a request is not ' +
          'blocked, it is interceptable and modifiable on the network path.',
        evidence: document.insecureSubresources.slice(0, 10).map((url) => ({
          kind: 'markup' as const,
          snippet: url,
        })),
        remediation:
          'Rewrite the references to https. If a dependency has no https endpoint, proxy it ' +
          'through your own origin rather than downgrading the page.',
        references: [
          {
            title: 'MDN: Mixed content',
            url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
          },
        ],
      } satisfies FindingInput,
    ];
  },
};

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}
