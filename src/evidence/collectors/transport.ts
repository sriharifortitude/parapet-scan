import { describeError } from '../../core/errors.js';
import type { Collector, TransportEvidence } from '../../types.js';

const NOT_PROBED: TransportEvidence = {
  httpProbed: false,
  httpReachable: false,
  redirectsToHttps: false,
};

/**
 * Asks for the plaintext form of an https target to see whether the origin
 * upgrades the connection. Redirects are deliberately not followed: the answer
 * is the first hop, and following the chain would hide a 200 served over http.
 */
export const transportCollector: Collector<'transport'> = {
  id: 'transport',
  description: 'Probes the http:// form of an https target to check for an upgrade.',
  dependsOn: [],

  async collect(ctx): Promise<TransportEvidence> {
    if (!ctx.target.isHttps) return NOT_PROBED;

    const plaintext = new URL(ctx.target.url.href);
    plaintext.protocol = 'http:';
    // A non-default https port does not imply the same port serves http.
    if (ctx.target.port !== 443) plaintext.port = '';

    try {
      const response = await ctx.http.request(plaintext, { followRedirects: false });
      const location = response.headers.get('location');
      const isRedirect = response.status >= 300 && response.status < 400 && location !== undefined;

      let redirectsToHttps = false;
      if (isRedirect && location !== undefined) {
        try {
          redirectsToHttps = new URL(location, plaintext).protocol === 'https:';
        } catch {
          redirectsToHttps = false;
        }
      }

      return {
        httpProbed: true,
        httpReachable: true,
        redirectsToHttps,
        firstHopStatus: response.status,
        ...(location === undefined ? {} : { firstHopLocation: location }),
      };
    } catch (error) {
      // Refusing plaintext connections outright is the desirable outcome, so a
      // connection failure here is recorded as "not reachable", not an error.
      void describeError(error);
      return { httpProbed: true, httpReachable: false, redirectsToHttps: false };
    }
  },
};
