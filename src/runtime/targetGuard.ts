import dns from 'node:dns';
import net from 'node:net';
import type { RuntimeTarget } from './types.js';

/**
 * The single choke point every outbound runtime-verification request must
 * pass through. Nothing in httpClient.ts is permitted to construct or
 * follow a URL without going through validateUrl()/validateRedirect() here.
 *
 * Defense in depth against SSRF:
 *  1. allowedOrigin is parsed strictly: http/https only, no embedded
 *     credentials, normalized host+port.
 *  2. The request path is checked for tricks that could make it resolve
 *     outside the origin (protocol-relative "//", embedded "@", backslash
 *     tricks, absolute URLs passed as a "path").
 *  3. The hostname is actually resolved via DNS, and *every* resolved IP is
 *     checked against private/loopback/link-local/metadata ranges -- so a
 *     hostname that looks fine but resolves to a private or metadata
 *     address is blocked (protects against DNS rebinding).
 *  4. Loopback (127.0.0.0/8, ::1) is allowed by default, matching the
 *     "default to local development targets" requirement. Any other
 *     private-range destination requires the caller to explicitly set
 *     allowPrivateNetworkTarget: true on the RuntimeTarget -- an attacker
 *     (or a careless caller) supplying an external-looking origin cannot
 *     silently get private-network access.
 *  5. Every redirect hop is re-validated with the same checks and must
 *     still resolve to the exact configured origin -- redirects are never
 *     allowed to leave allowedOrigin.
 */

export interface ValidationBlocked {
  ok: false;
  reason: string;
}

export interface ValidationOk {
  ok: true;
  url: URL;
}

export type ValidationResult = ValidationOk | ValidationBlocked;

interface ParsedOrigin {
  scheme: 'http:' | 'https:';
  hostname: string;
  port: number;
}

const CLOUD_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.goog',
  'metadata.azure.com',
  '100.100.100.200', // Alibaba Cloud metadata
  'fd00:ec2::254', // AWS IMDSv2 IPv6
]);

function blocked(reason: string): ValidationBlocked {
  return { ok: false, reason };
}

/** Parses and strictly validates the configured allowed origin. Rejects
 * anything that isn't exactly scheme://host[:port] with no path, query,
 * fragment, or embedded credentials. */
export function parseAllowedOrigin(raw: string): ParsedOrigin | ValidationBlocked {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return blocked(`allowedOrigin "${raw}" is not a valid URL.`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return blocked(`allowedOrigin scheme "${parsed.protocol}" is not permitted; only http/https are allowed.`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return blocked('allowedOrigin must not contain embedded credentials.');
  }
  if (parsed.pathname !== '' && parsed.pathname !== '/') {
    return blocked('allowedOrigin must not contain a path; configure the origin only (scheme://host[:port]).');
  }
  if (parsed.search !== '' || parsed.hash !== '') {
    return blocked('allowedOrigin must not contain a query string or fragment.');
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (hostname === '') {
    return blocked('allowedOrigin must specify a hostname.');
  }
  const port = parsed.port !== '' ? Number.parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  return { scheme: parsed.protocol as 'http:' | 'https:', hostname, port };
}

function ipVersion(ip: string): 4 | 6 | 0 {
  return net.isIP(ip) as 4 | 6 | 0;
}

/** True for loopback addresses: 127.0.0.0/8, ::1, and the literal "localhost". */
export function isLoopback(hostnameOrIp: string): boolean {
  const h = hostnameOrIp.toLowerCase();
  if (h === 'localhost') return true;
  if (ipVersion(h) === 4) return h.startsWith('127.');
  if (ipVersion(h) === 6) return h === '::1' || h === '0:0:0:0:0:0:0:1';
  return false;
}

/** True for RFC1918 / link-local / unique-local private network ranges.
 * Does NOT include loopback -- callers check isLoopback separately since
 * loopback has different default-allow treatment. */
export function isPrivateRange(ip: string): boolean {
  const version = ipVersion(ip);
  if (version === 4) {
    const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false;
    const [a, b] = parts as [number, number, number, number];
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 (link-local, includes cloud metadata)
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (carrier-grade NAT)
    if (a === 0) return true; // 0.0.0.0/8
    return false;
  }
  if (version === 6) {
    const h = ip.toLowerCase();
    if (h.startsWith('fc') || h.startsWith('fd')) return true; // fc00::/7 unique local
    if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true; // fe80::/10 link-local
    if (h.startsWith('::ffff:')) return isPrivateRange(h.slice(7)); // IPv4-mapped IPv6
    return false;
  }
  return false;
}

function isCloudMetadataDestination(hostnameOrIp: string): boolean {
  return CLOUD_METADATA_HOSTS.has(hostnameOrIp.toLowerCase());
}

async function resolveHostAddresses(hostname: string): Promise<string[]> {
  if (net.isIP(hostname) !== 0) return [hostname];
  try {
    const results = await dns.promises.lookup(hostname, { all: true, verbatim: true });
    return results.map((r) => r.address);
  } catch (e) {
    throw new Error(`DNS resolution failed for "${hostname}": ${(e as Error).message}`);
  }
}

/** Validates one hostname (from the allowed origin, or from a redirect
 * Location header) against the metadata/private-range/loopback rules.
 * Every resolved address must pass, not just one -- a hostname with mixed
 * public/private A records is rejected. */
async function validateHostname(hostname: string, allowPrivateNetworkTarget: boolean): Promise<ValidationBlocked | null> {
  if (isCloudMetadataDestination(hostname)) {
    return blocked(`Destination "${hostname}" is a cloud metadata address and is never permitted.`);
  }
  let addresses: string[];
  try {
    addresses = await resolveHostAddresses(hostname);
  } catch (e) {
    return blocked((e as Error).message);
  }
  if (addresses.length === 0) {
    return blocked(`Hostname "${hostname}" did not resolve to any address.`);
  }
  for (const addr of addresses) {
    if (isCloudMetadataDestination(addr)) {
      return blocked(`Destination "${hostname}" resolves to a cloud metadata address (${addr}) and is never permitted.`);
    }
    if (isLoopback(addr)) continue; // loopback always allowed
    if (isPrivateRange(addr)) {
      if (!allowPrivateNetworkTarget) {
        return blocked(
          `Destination "${hostname}" resolves to a private network address (${addr}). Set allowPrivateNetworkTarget: true on the RuntimeTarget to explicitly authorize testing a private/staging target.`
        );
      }
      continue;
    }
    // Public IP: only reachable at all if it also happens to equal the
    // configured allowedOrigin host (checked by the caller) -- but since
    // Phase 6 only ever tests local/staging targets, a public address here
    // means the configured origin is not local/private, which is fine as
    // long as it's the caller's own explicitly-authorized staging origin.
  }
  return null;
}

/** Validates the fully-configured RuntimeTarget itself (before any request
 * is made). This is the first gate: verify_finding must call this and
 * refuse to proceed at all if it fails. */
export async function validateTarget(target: RuntimeTarget): Promise<ValidationBlocked | null> {
  const parsed = parseAllowedOrigin(target.allowedOrigin);
  if ('reason' in parsed) return parsed;
  const hostBlock = await validateHostname(parsed.hostname, target.allowPrivateNetworkTarget === true);
  if (hostBlock) return hostBlock;
  return null;
}

const PATH_ESCAPE_RE = /^\s*\/\/|@|\\\\|^[a-zA-Z][a-zA-Z0-9+.-]*:/;
const ENCODED_PATH_ESCAPE_RE = /%2f|%5c|%40/i;

/** Builds and validates the full request URL for one call within an
 * already-validated target. Rejects any path that could smuggle an
 * absolute URL, protocol-relative reference, or embedded credentials past
 * the configured origin. */
export async function validateUrl(target: RuntimeTarget, path: string): Promise<ValidationResult> {
  const parsedOrigin = parseAllowedOrigin(target.allowedOrigin);
  if ('reason' in parsedOrigin) return blocked(parsedOrigin.reason);

  if (typeof path !== 'string' || path.length === 0 || !path.startsWith('/')) {
    return blocked(`Request path "${path}" must be a non-empty string starting with "/".`);
  }
  if (PATH_ESCAPE_RE.test(path) || ENCODED_PATH_ESCAPE_RE.test(path)) {
    return blocked(`Request path "${path}" contains a scheme, protocol-relative prefix, embedded credential, or backslash and is rejected.`);
  }

  const originStr = `${parsedOrigin.scheme}//${parsedOrigin.hostname}:${parsedOrigin.port}`;
  let url: URL;
  try {
    url = new URL(path, originStr);
  } catch {
    return blocked(`Could not construct a URL from path "${path}" against origin "${originStr}".`);
  }

  const originMatch = url.protocol === parsedOrigin.scheme && url.hostname.toLowerCase() === parsedOrigin.hostname && Number(url.port || (url.protocol === 'https:' ? 443 : 80)) === parsedOrigin.port;
  if (!originMatch) {
    return blocked(`Resolved URL "${url.toString()}" does not match the configured allowed origin "${originStr}".`);
  }

  const hostBlock = await validateHostname(parsedOrigin.hostname, target.allowPrivateNetworkTarget === true);
  if (hostBlock) return hostBlock;

  return { ok: true, url };
}

/** Validates a redirect Location header. The resulting URL must resolve to
 * the exact same origin as the target -- redirects are never allowed to
 * leave allowedOrigin, regardless of what the server sends. */
export async function validateRedirect(target: RuntimeTarget, location: string, currentUrl: URL): Promise<ValidationResult> {
  let resolved: URL;
  try {
    resolved = new URL(location, currentUrl);
  } catch {
    return blocked(`Redirect Location "${location}" is not a valid URL.`);
  }
  const parsedOrigin = parseAllowedOrigin(target.allowedOrigin);
  if ('reason' in parsedOrigin) return blocked(parsedOrigin.reason);
  const redirectPort = resolved.port !== '' ? Number.parseInt(resolved.port, 10) : resolved.protocol === 'https:' ? 443 : 80;
  if (
    resolved.protocol !== parsedOrigin.scheme ||
    resolved.hostname.toLowerCase().replace(/\.$/, '') !== parsedOrigin.hostname ||
    redirectPort !== parsedOrigin.port ||
    resolved.username !== '' ||
    resolved.password !== ''
  ) {
    return blocked(`Redirect destination "${resolved.toString()}" is outside the configured allowed origin.`);
  }
  const path = `${resolved.pathname}${resolved.search}`;
  return validateUrl(target, path === '' ? '/' : path).then((result) => {
    if (!result.ok) return result;
    // validateUrl already re-checked scheme/host/port against allowedOrigin.
    return result;
  });
}
