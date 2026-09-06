import type { Check, Evidence, FindingInput, Reference, Severity } from '../../types.js';

/**
 * Four headers that share the same shape: a single response header whose
 * absence is the finding, plus at most one weak-value case. Writing them as
 * four near-identical modules would be repetition without a difference, so
 * they are declared as data against one implementation.
 *
 * Headers whose verdict depends on another header -- framing, HSTS, CSP -- are
 * deliberately not expressed here; that interaction is what their own modules
 * exist to handle.
 */
interface DirectiveSpec {
  readonly checkId: string;
  readonly title: string;
  readonly header: string;
  readonly description: string;
  readonly references: readonly Reference[];
  readonly missing: {
    readonly id: string;
    readonly title: string;
    readonly severity: Severity;
    readonly summary: string;
    readonly remediation: string;
  };
  /** Returns a finding when the value that was sent is itself weak. */
  readonly weakValue?: (value: string) => Omit<FindingInput, 'evidence' | 'references'> | undefined;
}

function defineDirectiveCheck(spec: DirectiveSpec): Check {
  return {
    id: spec.checkId,
    title: spec.title,
    category: 'headers',
    description: spec.description,
    requires: ['baseline'],

    run(ctx) {
      const value = ctx.evidence('baseline').response.headers.get(spec.header);

      if (value === undefined) {
        return [
          {
            id: spec.missing.id,
            title: spec.missing.title,
            severity: spec.missing.severity,
            confidence: 'firm',
            summary: spec.missing.summary,
            evidence: [{ kind: 'missing-header', name: spec.header } satisfies Evidence],
            remediation: spec.missing.remediation,
            references: spec.references,
          },
        ];
      }

      const weak = spec.weakValue?.(value);
      if (weak === undefined) return [];

      return [
        {
          ...weak,
          evidence: [{ kind: 'header', name: spec.header, value } satisfies Evidence],
          references: spec.references,
        },
      ];
    },
  };
}

export const contentTypeOptionsCheck = defineDirectiveCheck({
  checkId: 'headers/content-type-options',
  title: 'X-Content-Type-Options',
  header: 'x-content-type-options',
  description: 'Checks that MIME sniffing is disabled.',
  references: [
    {
      title: 'MDN: X-Content-Type-Options',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
    },
  ],
  missing: {
    id: 'headers/content-type-options/missing',
    title: 'MIME sniffing is not disabled',
    severity: 'low',
    summary:
      'Without X-Content-Type-Options: nosniff, browsers may ignore the declared Content-Type ' +
      'and infer a type from the bytes. A user-uploaded file served as text or octet-stream ' +
      'can then be interpreted as script or stylesheet.',
    remediation: 'Send X-Content-Type-Options: nosniff on every response.',
  },
  weakValue: (value) =>
    value.trim().toLowerCase() === 'nosniff'
      ? undefined
      : {
          id: 'headers/content-type-options/invalid',
          title: `X-Content-Type-Options value "${value}" is not recognised`,
          severity: 'low',
          confidence: 'firm',
          summary:
            'nosniff is the only defined value. Anything else is ignored, so MIME sniffing ' +
            'remains enabled.',
          remediation: 'Set the header to exactly: nosniff',
        },
});

export const referrerPolicyCheck = defineDirectiveCheck({
  checkId: 'headers/referrer-policy',
  title: 'Referrer-Policy',
  header: 'referrer-policy',
  description: 'Checks whether outbound requests leak the full URL of the current page.',
  references: [
    {
      title: 'MDN: Referrer-Policy',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
    },
  ],
  missing: {
    id: 'headers/referrer-policy/missing',
    title: 'No Referrer-Policy header',
    severity: 'low',
    summary:
      'The browser default is strict-origin-when-cross-origin in current versions, but it is ' +
      'not guaranteed and older clients send the full URL. Where URLs carry session ' +
      'identifiers, reset tokens or record ids, those reach every third-party host the page ' +
      'links to or loads a resource from.',
    remediation:
      'Send Referrer-Policy: strict-origin-when-cross-origin, or no-referrer if no outbound ' +
      'referrer information is needed.',
  },
  weakValue: (value) => {
    const policy = value.trim().toLowerCase();
    if (policy !== 'unsafe-url' && policy !== 'no-referrer-when-downgrade') return undefined;
    return {
      id: 'headers/referrer-policy/permissive',
      title: `Referrer-Policy "${policy}" leaks full URLs`,
      severity: 'low',
      confidence: 'firm',
      summary:
        policy === 'unsafe-url'
          ? 'unsafe-url sends the complete URL, including path and query, to every origin the ' +
            'page requests -- including cross-origin ones over plaintext.'
          : 'no-referrer-when-downgrade sends the complete URL to every https origin, so any ' +
            'third-party host referenced by the page receives the full current URL.',
      remediation: 'Use strict-origin-when-cross-origin or a stricter policy.',
    };
  },
});

export const permissionsPolicyCheck = defineDirectiveCheck({
  checkId: 'headers/permissions-policy',
  title: 'Permissions-Policy',
  header: 'permissions-policy',
  description: 'Checks whether powerful browser features are explicitly restricted.',
  references: [
    {
      title: 'MDN: Permissions-Policy',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
    },
  ],
  missing: {
    id: 'headers/permissions-policy/missing',
    title: 'No Permissions-Policy header',
    severity: 'info',
    summary:
      'Powerful features -- camera, microphone, geolocation, payment -- are left at their ' +
      'defaults for the document and for anything it embeds. This is a hardening opportunity ' +
      'rather than a weakness on its own.',
    remediation:
      'Send a Permissions-Policy denying the features the application does not use, for ' +
      'example: camera=(), microphone=(), geolocation=(), payment=()',
  },
});

export const crossOriginOpenerCheck = defineDirectiveCheck({
  checkId: 'headers/cross-origin-opener',
  title: 'Cross-Origin-Opener-Policy',
  header: 'cross-origin-opener-policy',
  description: 'Checks whether the document is isolated from windows that open it.',
  references: [
    {
      title: 'MDN: Cross-Origin-Opener-Policy',
      url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
    },
  ],
  missing: {
    id: 'headers/cross-origin-opener/missing',
    title: 'No Cross-Origin-Opener-Policy header',
    severity: 'low',
    summary:
      'The document shares a browsing context group with any page that opens it, so a ' +
      'cross-origin opener retains a window reference and can navigate or probe it. This is ' +
      'the mechanism behind tabnabbing and it also blocks cross-origin isolation.',
    remediation: 'Send Cross-Origin-Opener-Policy: same-origin on document responses.',
  },
  weakValue: (value) =>
    value.trim().toLowerCase() === 'unsafe-none'
      ? {
          id: 'headers/cross-origin-opener/unsafe-none',
          title: 'Cross-Origin-Opener-Policy is explicitly disabled',
          severity: 'low',
          confidence: 'firm',
          summary:
            'unsafe-none is the default and restores the shared browsing context group. If ' +
            'this is set deliberately to support a cross-origin popup flow it is expected; ' +
            'otherwise it removes the isolation the header exists to provide.',
          remediation:
            'Use same-origin, or same-origin-allow-popups where the application opens ' +
            'cross-origin windows it needs to keep a handle on.',
        }
      : undefined,
});
