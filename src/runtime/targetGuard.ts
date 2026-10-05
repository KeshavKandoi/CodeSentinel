import dns from 'node:dns';
import net from 'node:net';
import type { RuntimeTarget } from './types.js';


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
  '100.100.100.200',
  'fd00:ec2::254',
]);

function blocked(reason: string): ValidationBlocked {
  return { ok: false, reason };
}

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

export function isLoopback(hostnameOrIp: string): boolean {
  const h = hostnameOrIp.toLowerCase();
  if (h === 'localhost') return true;
  if (ipVersion(h) === 4) return h.startsWith('127.');
  if (ipVersion(h) === 6) return h === '::1' || h === '0:0:0:0:0:0:0:1' || h.startsWith('::ffff:127.') || h.startsWith('::ffff:7f');
  return false;
}

export function isPrivateRange(ip: string): boolean {
  const version = ipVersion(ip);
  if (version === 4) {
    const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false;
    const [a, b] = parts as [number, number, number, number];
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 0) return true;
    return false;
  }
  if (version === 6) {
    const h = ip.toLowerCase();
    if (h.startsWith('fc') || h.startsWith('fd')) return true;
    if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true;
    if (h.startsWith('::ffff:')) return isPrivateRange(h.slice(7));
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

async function validateHostname(hostname: string, allowPrivateNetworkTarget: boolean): Promise<ValidationBlocked | null> {
  const bare = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(bare) === 0 && bare !== 'localhost') return blocked(`Destination "${hostname}" must be localhost or a literal IP address.`);
  if (isCloudMetadataDestination(hostname)) {
    return blocked(`Destination "${hostname}" is a cloud metadata address and is never permitted.`);
  }
  let addresses: string[];
  try {
    addresses = await resolveHostAddresses(bare);
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
    if (isLoopback(addr)) continue;
    if (isPrivateRange(addr)) {
      if (!allowPrivateNetworkTarget) {
        return blocked(
          `Destination "${hostname}" resolves to a private network address (${addr}). Set allowPrivateNetworkTarget: true on the RuntimeTarget to explicitly authorize testing a private/staging target.`
        );
      }
      continue;
    }
      return blocked(`Destination "${hostname}" resolves to a non-local address (${addr}); only loopback or explicitly authorized private-network targets are permitted.`);
  }
  return null;
}

export async function validateTarget(target: RuntimeTarget): Promise<ValidationBlocked | null> {
  const parsed = parseAllowedOrigin(target.allowedOrigin);
  if ('reason' in parsed) return parsed;
  const hostBlock = await validateHostname(parsed.hostname, target.allowPrivateNetworkTarget === true);
  if (hostBlock) return hostBlock;
  return null;
}

const PATH_ESCAPE_RE = /^\s*\/\/|@|\\\\|^[a-zA-Z][a-zA-Z0-9+.-]*:/;
const ENCODED_PATH_ESCAPE_RE = /%2f|%5c|%40/i;

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
    return result;
  });
}
