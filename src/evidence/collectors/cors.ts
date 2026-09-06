import { describeError } from '../../core/errors.js';
import type { Collector, CorsEvidence, CorsProbe, HttpResponse } from '../../types.js';

/**
 * Sends a small set of Origin values and records what comes back.
 *
 * Every probe is a plain GET or OPTIONS carrying an Origin header, which is
 * what any browser on any page already does. Nothing is written, no credential
 * is supplied, and the responses are only read for their CORS headers -- so
 * this stays within the "observe the configuration" boundary the tool commits
 * to in SECURITY.md.
 *
 * The .invalid TLD is reserved by RFC 2606 and can never be registered, so the
 * probe origins cannot collide with a real site the operator trusts.
 */
export const corsCollector: Collector<'cors'> = {
  id: 'cors',
  description: 'Replays the request with attacker-controlled Origin values.',
  dependsOn: ['baseline'],

  async collect(ctx): Promise<CorsEvidence> {
    const { response } = ctx.evidence('baseline');
    const url = response.url;
    const host = ctx.target.hostname;

    const cases: ReadonlyArray<{ origin: string; label: CorsProbe['label']; method: string }> = [
      { origin: 'https://bastion-probe.invalid', label: 'arbitrary', method: 'GET' },
      { origin: 'null', label: 'null', method: 'GET' },
      // Catches allowlists implemented with a prefix or substring match.
      { origin: `https://${host}.bastion-probe.invalid`, label: 'subdomain-suffix', method: 'GET' },
      { origin: 'https://bastion-probe.invalid', label: 'preflight', method: 'OPTIONS' },
    ];

    const probes: CorsProbe[] = [];
    for (const testCase of cases) {
      const headers: Record<string, string> = { origin: testCase.origin };
      if (testCase.method === 'OPTIONS') {
        headers['access-control-request-method'] = 'PUT';
        headers['access-control-request-headers'] = 'authorization,content-type';
      }

      let response2: HttpResponse;
      try {
        response2 = await ctx.http.request(url, {
          method: testCase.method,
          headers,
          followRedirects: false,
          maxBodyBytes: 1024,
        });
      } catch (error) {
        void describeError(error);
        continue;
      }

      probes.push({
        sentOrigin: testCase.origin,
        label: testCase.label,
        status: response2.status,
        ...pick(response2, 'access-control-allow-origin', 'allowOrigin'),
        ...pick(response2, 'access-control-allow-credentials', 'allowCredentials'),
        ...pick(response2, 'access-control-allow-methods', 'allowMethods'),
        ...pick(response2, 'access-control-allow-headers', 'allowHeaders'),
      });
    }

    return { probes };
  },
};

function pick<K extends string>(
  response: HttpResponse,
  header: string,
  key: K,
): Partial<Record<K, string>> {
  const value = response.headers.get(header);
  return value === undefined ? {} : ({ [key]: value } as Record<K, string>);
}
