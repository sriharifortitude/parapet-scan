import { createRequire } from 'node:module';

interface PackageManifest {
  readonly name: string;
  readonly version: string;
}

/**
 * Read at runtime rather than duplicated as a constant, so the version in
 * reports and in the SARIF tool block cannot drift from the published package.
 * The relative path resolves identically from src/ under tsx and from dist/.
 */
const manifest = createRequire(import.meta.url)('../package.json') as PackageManifest;

export const TOOL_NAME = manifest.name;
export const TOOL_VERSION = manifest.version;
export const TOOL_URL = 'https://github.com/sriharifortitude/bastion-scan';
export const USER_AGENT = `${TOOL_NAME}/${TOOL_VERSION} (+${TOOL_URL})`;
