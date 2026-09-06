import type { Check } from '../../types.js';

const REFERENCE = {
  title: 'OWASP Transport Layer Security Cheat Sheet',
  url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
};

export const plaintextTransportCheck: Check = {
  id: 'tls/plaintext-transport',
  title: 'Plaintext availability',
  category: 'tls',
  description: 'Checks whether the origin still serves content over http without redirecting.',
  requires: ['transport'],

  run(ctx) {
    // A target given as http:// is a statement about the deployment, not a
    // finding about a redirect, so it is reported once and directly.
    if (!ctx.target.isHttps) {
      return [
        {
          id: 'tls/plaintext-transport/http-target',
          title: 'Target is served over plaintext http',
          severity: 'high',
          confidence: 'confirmed',
          summary:
            'The scan target itself is an http URL. Everything the application sends and ' +
            'receives, credentials and session cookies included, travels unencrypted and can ' +
            'be read or modified by anyone on the network path.',
          evidence: [{ kind: 'note', text: `Scanned ${ctx.target.origin} over http.` }],
          remediation:
            'Terminate TLS on this origin and redirect http to https, then add HSTS once the ' +
            'https path is confirmed stable.',
          references: [REFERENCE],
        },
      ];
    }

    const transport = ctx.evidence('transport');
    if (!transport.httpProbed || !transport.httpReachable || transport.redirectsToHttps) {
      return [];
    }

    const status = transport.firstHopStatus;
    const isRedirect = status !== undefined && status >= 300 && status < 400;

    return [
      {
        id: isRedirect
          ? 'tls/plaintext-transport/redirects-to-http'
          : 'tls/plaintext-transport/served-over-http',
        title: isRedirect
          ? 'Plaintext requests are redirected, but not to https'
          : 'Content is served over plaintext http',
        severity: 'medium',
        confidence: 'confirmed',
        summary: isRedirect
          ? `The http endpoint answered ${status} with a Location of ` +
            `${transport.firstHopLocation ?? '(none)'}, which does not upgrade the connection. ` +
            'The first request of a session is still made in the clear.'
          : `The http endpoint answered ${status ?? 'a non-redirect status'} directly instead ` +
            'of redirecting. Users and links that reach the plaintext origin stay there, so ' +
            'the https deployment is bypassed rather than enforced.',
        evidence: [
          {
            kind: 'exchange',
            method: 'GET',
            url: `http://${ctx.target.hostname}/`,
            status: status ?? 0,
            ...(transport.firstHopLocation === undefined
              ? {}
              : { responseHeaders: { location: transport.firstHopLocation } }),
          },
        ],
        remediation:
          'Return a 301 to the https URL for every http request, then send HSTS on the https ' +
          'responses so subsequent visits never make the plaintext request at all.',
        references: [REFERENCE],
      },
    ];
  },
};
