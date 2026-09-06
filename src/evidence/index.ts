import { baselineCollector } from './collectors/baseline.js';
import { corsCollector } from './collectors/cors.js';
import { documentCollector } from './collectors/document.js';
import { exposureCollector } from './collectors/exposure.js';
import { tlsCollector } from './collectors/tls.js';
import { transportCollector } from './collectors/transport.js';
import { wellKnownCollector } from './collectors/well-known.js';
import type { AnyCollector, CollectorId } from '../types.js';

/** Declaration order is irrelevant; the engine sorts by `dependsOn`. */
export const COLLECTORS: readonly AnyCollector[] = [
  baselineCollector,
  transportCollector,
  tlsCollector,
  documentCollector,
  corsCollector,
  wellKnownCollector,
  exposureCollector,
];

export function collectorById(id: CollectorId): AnyCollector {
  const collector = COLLECTORS.find((candidate) => candidate.id === id);
  if (collector === undefined) throw new Error(`Unknown collector: ${id}`);
  return collector;
}
