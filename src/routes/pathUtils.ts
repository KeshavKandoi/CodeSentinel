import type { HttpMethod, RouteParameter } from './types.js';

const KNOWN_METHODS: readonly HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ALL'];

export function toHttpMethod(name: string): HttpMethod {
  const upper = name.trim().toUpperCase();
  const found = KNOWN_METHODS.find((m) => m === upper);
  return found ?? 'unknown';
}

/** Joins route fragments into one normalized path: leading slash, no doubled or trailing slashes. */
export function joinRoutePath(...parts: string[]): string {
  const segments: string[] = [];
  for (const part of parts) {
    for (const seg of part.split('/')) {
      if (seg.length > 0) segments.push(seg);
    }
  }
  return '/' + segments.join('/');
}

export function pathStartsWith(full: string, prefix: string): boolean {
  const f = joinRoutePath(full);
  const p = joinRoutePath(prefix);
  if (p === '/') return true;
  return f === p || f.startsWith(p + '/');
}

export function makeParam(name: string, type = 'unknown', required: boolean | 'unknown' = 'unknown'): RouteParameter {
  return { name, type, required };
}

/** Express/Fastify/Nest style `:id` and `:id?` parameters. */
export function expressPathParams(routePath: string): RouteParameter[] {
  const out: RouteParameter[] = [];
  const re = /:([A-Za-z_]\w*)(\?)?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(routePath)) !== null) {
    const name = m[1];
    if (name) out.push(makeParam(name, 'string', m[2] === undefined));
  }
  return out;
}

export function dedupeParams(params: readonly RouteParameter[]): RouteParameter[] {
  const seen = new Set<string>();
  const out: RouteParameter[] = [];
  for (const p of params) {
    if (seen.has(p.name)) continue;
    seen.add(p.name);
    out.push(p);
  }
  return out;
}
