import { describeError } from '../../core/errors.js';
import type { Collector, WellKnownEvidence } from '../../types.js';

/** Two fixed, universally expected paths. Neither is sensitive. */
export const wellKnownCollector: Collector<'well-known'> = {
  id: 'well-known',
  description: 'Looks for security.txt (RFC 9116) and robots.txt.',
  dependsOn: [],

  async collect(ctx): Promise<WellKnownEvidence> {
    const [securityTxt, robotsTxt] = await Promise.all([
      probe(ctx.http, new URL('/.well-known/security.txt', ctx.target.url)),
      probe(ctx.http, new URL('/robots.txt', ctx.target.url)),
    ]);

    return {
      ...(securityTxt === undefined ? {} : { securityTxt }),
      ...(robotsTxt === undefined ? {} : { robotsTxt }),
    };
  },
};

async function probe(
  http: Parameters<Collector<'well-known'>['collect']>[0]['http'],
  url: URL,
): Promise<{ url: string; status: number } | undefined> {
  try {
    const response = await http.request(url, { followRedirects: false, maxBodyBytes: 4096 });
    return { url: url.href, status: response.status };
  } catch (error) {
    void describeError(error);
    return undefined;
  }
}
