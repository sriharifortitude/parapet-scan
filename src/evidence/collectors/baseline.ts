import type { Collector } from '../../types.js';

/**
 * The single fetch every other part of the scan is built on. Redirects are
 * followed, so `response.url` is the document that actually got served and the
 * headers belong to that document rather than to an intermediate 301.
 */
export const baselineCollector: Collector<'baseline'> = {
  id: 'baseline',
  description: 'Fetches the target document, following redirects.',
  dependsOn: [],

  async collect(ctx) {
    const response = await ctx.http.request(ctx.target.url);
    return { response };
  },
};
