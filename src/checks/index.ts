import { cookieAttributesCheck } from './cookies/attributes.js';
import { corsMisconfigurationCheck } from './cors/misconfiguration.js';
import { insecureFormCheck, targetBlankCheck } from './content/markup.js';
import { mixedContentCheck, subresourceIntegrityCheck } from './content/subresources.js';
import { exposedPathsCheck } from './disclosure/exposed-paths.js';
import { securityTxtCheck } from './disclosure/security-txt.js';
import { serverBannerCheck } from './disclosure/server-banner.js';
import { cspCheck } from './headers/csp.js';
import {
  contentTypeOptionsCheck,
  crossOriginOpenerCheck,
  permissionsPolicyCheck,
  referrerPolicyCheck,
} from './headers/directives.js';
import { framingCheck } from './headers/framing.js';
import { hstsCheck } from './headers/hsts.js';
import { tlsCertificateCheck } from './tls/certificate.js';
import { tlsProtocolsCheck } from './tls/protocols.js';
import { plaintextTransportCheck } from './tls/transport.js';
import type { Category, Check } from '../types.js';

export const CHECKS: readonly Check[] = [
  cspCheck,
  hstsCheck,
  framingCheck,
  contentTypeOptionsCheck,
  referrerPolicyCheck,
  permissionsPolicyCheck,
  crossOriginOpenerCheck,
  cookieAttributesCheck,
  corsMisconfigurationCheck,
  plaintextTransportCheck,
  tlsProtocolsCheck,
  tlsCertificateCheck,
  serverBannerCheck,
  exposedPathsCheck,
  securityTxtCheck,
  subresourceIntegrityCheck,
  mixedContentCheck,
  insecureFormCheck,
  targetBlankCheck,
];

/**
 * Duplicate ids would make --disable and the baseline file ambiguous, so the
 * registry is validated once at import rather than trusted by convention.
 */
const duplicates = CHECKS.map((check) => check.id).filter(
  (id, index, all) => all.indexOf(id) !== index,
);
if (duplicates.length > 0) {
  throw new Error(`Duplicate check ids in the registry: ${duplicates.join(', ')}`);
}

export function selectChecks(options: {
  readonly disabled: readonly string[];
  readonly categories: readonly Category[];
}): readonly Check[] {
  const disabled = new Set(options.disabled);
  const categories = new Set(options.categories);

  return CHECKS.filter((check) => {
    if (disabled.has(check.id)) return false;
    if (categories.size > 0 && !categories.has(check.category)) return false;
    return true;
  });
}
