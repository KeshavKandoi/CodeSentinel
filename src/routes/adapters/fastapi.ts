import type { Evidence } from '../../discovery/types.js';
import { buildEntry, unique } from '../entryFactory.js';
import { dedupeParams, expressPathParams, joinRoutePath, makeParam, toHttpMethod } from '../pathUtils.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const PY_EXTS = ['.py'] as const;
const FASTAPI_RE = /\bfrom\s+fastapi\s+import\b|\bimport\s+fastapi\b|\bFastAPI\s*\(|\bAPIRouter\s*\(/;
const ROUTE_DECORATOR_RE = /@([A-Za-z_]\w*)\s*\.\s*(get|post|put|patch|delete|head|options|api_route)\s*\(([^)]*)\)\s*\n\s*(?:async\s+def|def)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/g;

function stripPyComments(src: string): string {
  return src
    .split('\n')
    .map((line) => {
      const idx = line.indexOf('#');
      return idx >= 0 ? `${line.slice(0, idx)}${' '.repeat(line.length - idx)}` : line;
    })
    .join('\n');
}

function lineAt(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}

function stringProp(args: string, name: string): string | null {
  const re = new RegExp(`${name}\\s*=\\s*(['"])(.*?)\\1`);
  return re.exec(args)?.[2] ?? null;
}

function firstString(args: string): string | null {
  return /^\s*(['"])(.*?)\1/.exec(args)?.[2] ?? null;
}

function listMethods(args: string, fallback: string): HttpMethod[] {
  if (fallback !== 'api_route') return [toHttpMethod(fallback)];
  const raw = /methods\s*=\s*\[([^\]]+)\]/.exec(args)?.[1];
  if (!raw) return ['unknown'];
  const out: HttpMethod[] = [];
  const re = /['"]([A-Z]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) out.push(toHttpMethod(m[1] ?? ''));
  return out.length > 0 ? out : ['unknown'];
}

function collectRouterPrefixes(code: string): Map<string, string | null> {
  const out = new Map<string, string | null>();
  const re = /([A-Za-z_]\w*)\s*=\s*(?:FastAPI|APIRouter)\s*\(([^)]*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) out.set(m[1] ?? '', stringProp(m[2] ?? '', 'prefix') ?? '');
  return out;
}

function collectIncludes(code: string): Map<string, string | null> {
  const out = new Map<string, string | null>();
  const re = /([A-Za-z_]\w*)\s*\.\s*include_router\s*\(\s*([A-Za-z_]\w*)\s*(?:,\s*([^)]*))?\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const child = m[2] ?? '';
    const prefix = stringProp(m[3] ?? '', 'prefix') ?? '';
    out.set(child, prefix);
  }
  return out;
}

function paramsFromSignature(signature: string): { query: RouteParameter[]; body: RouteParameter[]; deps: string[]; auth: string[]; authz: string[]; uploads: string[] } {
  const query: RouteParameter[] = [];
  const body: RouteParameter[] = [];
  const deps: string[] = [];
  const auth: string[] = [];
  const authz: string[] = [];
  const uploads: string[] = [];
  for (const raw of signature.split(',')) {
    const part = raw.trim();
    const name = /^([A-Za-z_]\w*)/.exec(part)?.[1];
    if (!name || ['self', 'request'].includes(name)) continue;
    if (/\bDepends\s*\(/.test(part)) {
      const dep = /Depends\s*\(\s*([A-Za-z_][\w.]*)?/.exec(part)?.[1] ?? 'Depends';
      deps.push(dep);
      if (/auth|jwt|token|user|oauth|bearer/i.test(dep)) auth.push(dep);
      if (/admin|role|permission|scope|policy/i.test(dep)) authz.push(dep);
      continue;
    }
    if (/\b(Security|OAuth2|HTTPBearer|APIKey)/.test(part)) auth.push(part);
    if (/\bUploadFile\b|\bFile\s*\(/.test(part)) uploads.push(name);
    if (/\bBody\s*\(/.test(part) || /\bBaseModel\b/.test(part)) body.push(makeParam(name));
    else query.push(makeParam(name));
  }
  return { query, body, deps, auth, authz, uploads };
}

export const fastapiAdapter: FrameworkAdapter = {
  id: 'fastapi',
  ecosystems: ['python'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'python') return false;
    return ctx.listSourceFiles(PY_EXTS).some((file) => {
      const src = ctx.readSource(file);
      return src !== null && FASTAPI_RE.test(stripPyComments(src.content));
    });
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const entries: AttackSurfaceEntry[] = [];
    const mergedCodeByFile = new Map<string, string>();
    for (const file of ctx.listSourceFiles(PY_EXTS)) {
      const src = ctx.readSource(file);
      if (src) mergedCodeByFile.set(file, stripPyComments(src.content));
    }
    for (const [file, code] of mergedCodeByFile) {
      if (!FASTAPI_RE.test(code)) continue;
      const routerPrefixes = collectRouterPrefixes(code);
      const includes = collectIncludes(code);
      let m: RegExpExecArray | null;
      while ((m = ROUTE_DECORATOR_RE.exec(code)) !== null) {
        const receiver = m[1] ?? '';
        const verb = m[2] ?? '';
        const args = m[3] ?? '';
        const handler = m[4] ?? 'unknown';
        const signature = m[5] ?? '';
        const routePath = firstString(args);
        const receiverPrefix = routerPrefixes.get(receiver);
        const includePrefix = includes.get(receiver) ?? '';
        const resolved = routePath !== null && receiverPrefix !== null && includePrefix !== null;
        const fullPath = resolved ? joinRoutePath(includePrefix ?? '', receiverPrefix ?? '', routePath ?? '') : 'unknown';
        const p = paramsFromSignature(signature);
        const evidence: Evidence[] = [{ source: `${file}:${lineAt(code, m.index)}`, detail: `FastAPI @${receiver}.${verb} route decorator.` }];
        if (!resolved) evidence.push({ source: `${file}:${lineAt(code, m.index)}`, detail: 'Router prefix or route path is not statically resolvable; path recorded as unknown.' });

        for (const method of listMethods(args, verb)) {
          entries.push(
            buildEntry({
              framework: 'fastapi',
              method,
              path: fullPath,
              pathResolved: resolved,
              file,
              line: lineAt(code, m.index),
              endLine: lineAt(code, m.index),
              handler,
              controller: 'unknown',
              router: receiver,
              middleware: [],
              dependencies: p.deps,
              parameters: dedupeParams(expressPathParams(fullPath)),
              queryParameters: p.query,
              bodyParameters: p.body,
              extraAuth: p.auth,
              extraAuthz: p.authz,
              uploadIndicators: p.uploads.map((u) => `parameter: ${u}`),
              responseIndicators: [],
              confidence: resolved ? 'high' : 'low',
              evidence,
            })
          );
        }
      }
    }
    return entries;
  },
};
