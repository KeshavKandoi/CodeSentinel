import type { Evidence } from '../../discovery/types.js';
import { detectUploadIndicators, inlineAuthIndicators } from '../authHeuristics.js';
import { buildEntry } from '../entryFactory.js';
import { buildLineIndex, extractResponseIndicators, findFunctionBody, lineAtIndex, stripJsComments } from '../jsScanner.js';
import { makeParam } from '../pathUtils.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'] as const;
const METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

function hasNextProfile(ctx: AdapterContext): boolean {
  return (
    ctx.profile.dependencies.some((d) => d.name === 'next') ||
    ctx.profile.frameworks.frontend.some((f) => f.name.toLowerCase() === 'next.js')
  );
}

function pagesApiPath(file: string): string | null {
  const marker = '/pages/api/';
  const idx = `/${file}`.indexOf(marker);
  if (idx < 0) return null;
  const rel = `/${file}`.slice(idx + marker.length).replace(/\.(tsx?|jsx?|mjs|cjs)$/, '').replace(/\/index$/, '');
  return '/api' + normalizeNextSegments(rel);
}

function appRoutePath(file: string): string | null {
  const normalized = `/${file}`;
  const match = /\/(?:src\/)?app\/(.+)\/route\.(?:tsx?|jsx?|mjs|cjs)$/.exec(normalized);
  if (!match) return null;
  return normalizeNextSegments(match[1] ?? '');
}

function normalizeNextSegments(rel: string): string {
  const parts = rel.split('/').filter((part) => part.length > 0 && !part.startsWith('('));
  const mapped = parts.map((part) => {
    const optional = /^\[\[\.\.\.([^\]]+)\]\]$/.exec(part);
    if (optional) return `:${optional[1]}*`;
    const catchAll = /^\[\.\.\.([^\]]+)\]$/.exec(part);
    if (catchAll) return `:${catchAll[1]}*`;
    const dyn = /^\[([^\]]+)\]$/.exec(part);
    if (dyn) return `:${dyn[1]}`;
    return part;
  });
  return '/' + mapped.join('/');
}

function paramsFor(routePath: string): RouteParameter[] {
  const out: RouteParameter[] = [];
  const re = /:([A-Za-z_]\w*)(\*)?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(routePath)) !== null) out.push(makeParam(m[1] ?? '', 'string', m[2] === undefined ? true : 'unknown'));
  return out;
}

function pagesMethods(code: string): HttpMethod[] {
  const methods = new Set<HttpMethod>();
  const re = /\breq\s*\.\s*method\s*={0,2}=+\s*['"]([A-Z]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const raw = m[1] ?? '';
    const method = METHODS.find((x) => x === raw);
    if (method) methods.add(method);
  }
  if (methods.size === 0) return ['ALL'];
  return Array.from(methods);
}

function exportedMethods(code: string): Array<{ method: HttpMethod; lineIdx: number; body: string; handler: string }> {
  const out: Array<{ method: HttpMethod; lineIdx: number; body: string; handler: string }> = [];
  for (const method of METHODS) {
    const declRe = new RegExp(`export\\s+(?:async\\s+)?function\\s+${method}\\s*\\(`, 'g');
    let m: RegExpExecArray | null;
    while ((m = declRe.exec(code)) !== null) out.push({ method, lineIdx: m.index, body: findFunctionBody(code, method) ?? '', handler: method });
    const constRe = new RegExp(`export\\s+const\\s+${method}\\s*=`, 'g');
    let cm: RegExpExecArray | null;
    while ((cm = constRe.exec(code)) !== null) out.push({ method, lineIdx: cm.index, body: '', handler: method });
  }
  return out;
}

export const nextjsAdapter: FrameworkAdapter = {
  id: 'nextjs',
  ecosystems: ['node'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'node' || !hasNextProfile(ctx)) return false;
    return ctx.listSourceFiles(JS_EXTS).some((file) => pagesApiPath(file) !== null || appRoutePath(file) !== null);
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const entries: AttackSurfaceEntry[] = [];
    for (const file of ctx.listSourceFiles(JS_EXTS)) {
      const src = ctx.readSource(file);
      if (!src) continue;
      const code = stripJsComments(src.content);
      const lineStarts = buildLineIndex(code);
      const pagesPath = pagesApiPath(file);
      const appPath = appRoutePath(file);
      const routePath = pagesPath ?? appPath;
      if (!routePath) continue;

      const methodDefs = appPath ? exportedMethods(code) : pagesMethods(code).map((method) => ({ method, lineIdx: 0, body: code, handler: 'default export' }));
      if (methodDefs.length === 0) continue;
      for (const def of methodDefs) {
        const line = lineAtIndex(lineStarts, def.lineIdx);
        const inline = inlineAuthIndicators(def.body || code);
        const evidence: Evidence[] = [{ source: `${file}:${line}`, detail: appPath ? `Next.js App Router ${def.method} export.` : 'Next.js Pages Router API route file.' }];
        entries.push(
          buildEntry({
            framework: 'nextjs',
            method: def.method,
            path: routePath,
            pathResolved: true,
            file,
            line,
            endLine: line,
            handler: def.handler,
            controller: 'unknown',
            router: appPath ? 'app-router' : 'pages-router',
            middleware: [],
            dependencies: [],
            parameters: paramsFor(routePath),
            queryParameters: [],
            bodyParameters: [],
            extraAuth: inline.authn,
            extraAuthz: inline.authz,
            uploadIndicators: detectUploadIndicators([], def.body || code),
            responseIndicators: extractResponseIndicators(def.body || code),
            confidence: 'high',
            evidence,
          })
        );
      }
    }
    return entries;
  },
};
