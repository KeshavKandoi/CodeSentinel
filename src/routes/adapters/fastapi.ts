import type { Evidence } from '../../discovery/types.js';
import { buildEntry, unique } from '../entryFactory.js';
import { dedupeParams, joinRoutePath, makeParam, toHttpMethod } from '../pathUtils.js';
import { lineOf, matchClose, scanPython, splitTopLevel } from '../pyScanner.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const PY_EXTS = ['.py'] as const;
const FASTAPI_RE = /\bfrom\s+fastapi\s+import\b|\bimport\s+fastapi\b|\bFastAPI\s*\(|\bAPIRouter\s*\(/;
const ROUTE_START_RE = /@([A-Za-z_]\w*)\s*\.\s*(get|post|put|patch|delete|head|options|api_route)\s*\(/g;
const NODE_START_RE = /\b([A-Za-z_]\w*)\s*=\s*(?:FastAPI|APIRouter)\s*\(/g;
const INCLUDE_START_RE = /\b([A-Za-z_]\w*)\s*\.\s*include_router\s*\(/g;
const DEPENDENCY_RE = /\b(Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)?/;
const AUTHN_DEP_RE = /auth|jwt|token|user|oauth|bearer/i;
const AUTHZ_DEP_RE = /admin|role|permission|scope|policy/i;
const SECURITY_TYPE_RE = /\b(?:HTTPBearer|HTTPAuthorizationCredentials|OAuth2PasswordBearer|OAuth2AuthorizationCodeBearer|APIKeyHeader|APIKeyCookie|APIKeyQuery|HTTPBasic|HTTPBasicCredentials)\b/;

interface NodeInfo {
  prefix: string | null;
  deps: string[];
}

interface IncludeInfo extends NodeInfo {
  parent: string;
}

function stringProp(args: string, name: string): string | null {
  const re = new RegExp(`\\b${name}\\s*=\\s*(['"])(.*?)\\1`);
  return re.exec(args)?.[2] ?? null;
}

function firstString(args: string): string | null {
  return /^\s*(['"])(.*?)\1/.exec(args)?.[2] ?? null;
}

function prefixOf(args: string): string | null {
  if (!/\bprefix\s*=/.test(args)) return '';
  return stringProp(args, 'prefix');
}

function listMethods(args: string, fallback: string): HttpMethod[] {
  if (fallback !== 'api_route') return [toHttpMethod(fallback)];
  const raw = /methods\s*=\s*\[([^\]]+)\]/.exec(args)?.[1];
  if (!raw) return ['unknown'];
  const out: HttpMethod[] = [];
  const re = /['"]([A-Za-z]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) out.push(toHttpMethod(m[1] ?? ''));
  return out.length > 0 ? out : ['unknown'];
}

function dependencyList(args: string): string[] {
  const start = /\bdependencies\s*=\s*\[/.exec(args);
  if (!start) return [];
  const open = start.index + start[0].length - 1;
  const close = matchClose(args, open);
  const inner = args.slice(open + 1, close === -1 ? args.length : close);
  const out: string[] = [];
  const re = /\b(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) out.push(m[1] ?? 'Depends');
  return out;
}

function collectNodes(code: string): Map<string, NodeInfo> {
  const out = new Map<string, NodeInfo>();
  const re = new RegExp(NODE_START_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(code, open);
    const args = close === -1 ? '' : code.slice(open + 1, close);
    out.set(m[1] ?? '', { prefix: prefixOf(args), deps: dependencyList(args) });
  }
  return out;
}

function collectIncludes(code: string): Map<string, IncludeInfo> {
  const out = new Map<string, IncludeInfo>();
  const re = new RegExp(INCLUDE_START_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(code, open);
    if (close === -1) continue;
    const parts = splitTopLevel(code.slice(open + 1, close));
    const child = /^([A-Za-z_]\w*)$/.exec(parts[0] ?? '')?.[1];
    if (!child) continue;
    const rest = parts.slice(1).join(', ');
    out.set(child, { prefix: prefixOf(rest), deps: dependencyList(rest), parent: m[1] ?? '' });
  }
  return out;
}

function resolveChain(
  receiver: string,
  nodes: ReadonlyMap<string, NodeInfo>,
  includes: ReadonlyMap<string, IncludeInfo>
): { prefixes: Array<string | null>; deps: string[] } {
  const prefixes: Array<string | null> = [];
  const deps: string[] = [];
  const seen = new Set<string>();
  let current: string = receiver;
  while (current !== '' && !seen.has(current)) {
    seen.add(current);
    const node = nodes.get(current);
    if (node) {
      prefixes.unshift(node.prefix);
      deps.push(...node.deps);
    }
    const included = includes.get(current);
    if (!included) break;
    prefixes.unshift(included.prefix);
    deps.push(...included.deps);
    current = included.parent;
  }
  return { prefixes, deps };
}

function fastapiPathParams(routePath: string): RouteParameter[] {
  const out: RouteParameter[] = [];
  const re = /\{([A-Za-z_]\w*)(?::[^}]*)?\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(routePath)) !== null) out.push(makeParam(m[1] ?? '', 'string', true));
  return out;
}

interface SignatureInfo {
  query: RouteParameter[];
  body: RouteParameter[];
  deps: string[];
  auth: string[];
  authz: string[];
  uploads: string[];
}

function paramsFromSignature(signature: string): SignatureInfo {
  const info: SignatureInfo = { query: [], body: [], deps: [], auth: [], authz: [], uploads: [] };
  for (const raw of splitTopLevel(signature)) {
    const part = raw.trim();
    const name = /^([A-Za-z_]\w*)/.exec(part)?.[1];
    if (!name || ['self', 'request', 'response', 'background_tasks'].includes(name)) continue;
    const dep = DEPENDENCY_RE.exec(part);
    if (dep) {
      const depName = dep[2] ?? dep[1] ?? 'Depends';
      info.deps.push(depName);
      if (dep[1] === 'Security' || AUTHN_DEP_RE.test(depName) || SECURITY_TYPE_RE.test(part)) info.auth.push(depName);
      if (AUTHZ_DEP_RE.test(depName) || (dep[1] === 'Security' && /scopes\s*=/.test(part))) info.authz.push(depName);
      continue;
    }
    if (SECURITY_TYPE_RE.test(part)) info.auth.push(part);
    if (/\bUploadFile\b|\bFile\s*\(/.test(part)) info.uploads.push(name);
    if (/\bBody\s*\(/.test(part) || /\bBaseModel\b/.test(part)) info.body.push(makeParam(name));
    else info.query.push(makeParam(name));
  }
  return info;
}

interface Definition {
  name: string;
  sigOpen: number;
  sigClose: number;
}

function findDefinition(code: string, from: number): Definition | null {
  let pos = from;
  for (let guard = 0; guard < 12; guard++) {
    while (pos < code.length && /\s/.test(code.charAt(pos))) pos++;
    if (code.charAt(pos) !== '@') break;
    const nm = /^@[A-Za-z_][\w.]*/.exec(code.slice(pos, pos + 200));
    if (!nm) return null;
    let next = pos + nm[0].length;
    if (code.charAt(next) === '(') {
      const close = matchClose(code, next);
      if (close === -1) return null;
      next = close + 1;
    }
    pos = next;
  }
  const d = /^(?:async\s+def|def)\s+([A-Za-z_]\w*)\s*\(/.exec(code.slice(pos, pos + 200));
  if (!d) return null;
  const sigOpen = pos + d[0].length - 1;
  const sigClose = matchClose(code, sigOpen);
  if (sigClose === -1) return null;
  return { name: d[1] ?? 'unknown', sigOpen, sigClose };
}

export const fastapiAdapter: FrameworkAdapter = {
  id: 'fastapi',
  ecosystems: ['python'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'python') return false;
    return ctx.listSourceFiles(PY_EXTS).some((file) => {
      const src = ctx.readSource(file);
      return src !== null && FASTAPI_RE.test(scanPython(src.content).code);
    });
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const entries: AttackSurfaceEntry[] = [];
    for (const file of ctx.listSourceFiles(PY_EXTS)) {
      const src = ctx.readSource(file);
      if (!src) continue;
      const code = scanPython(src.content).code;
      if (!FASTAPI_RE.test(code)) continue;
      const nodes = collectNodes(code);
      const includes = collectIncludes(code);
      const routeRe = new RegExp(ROUTE_START_RE.source, 'g');
      let m: RegExpExecArray | null;
      while ((m = routeRe.exec(code)) !== null) {
        const receiver = m[1] ?? '';
        const verb = m[2] ?? '';
        const open = m.index + m[0].length - 1;
        const close = matchClose(code, open);
        if (close === -1) continue;
        const def = findDefinition(code, close + 1);
        if (!def) continue;
        const args = code.slice(open + 1, close);
        const routePath = firstString(args) ?? stringProp(args, 'path');
        const chain = resolveChain(receiver, nodes, includes);
        const resolved = routePath !== null && chain.prefixes.every((p) => p !== null);
        const fullPath = resolved ? joinRoutePath(...chain.prefixes.map((p) => p ?? ''), routePath ?? '') : 'unknown';
        const signature = paramsFromSignature(code.slice(def.sigOpen + 1, def.sigClose));
        const decoratorDeps = dependencyList(args);
        const routeLevelDeps = [...chain.deps, ...decoratorDeps];
        const pathParams = dedupeParams(fastapiPathParams(resolved ? fullPath : routePath ?? ''));
        const pathNames = new Set(pathParams.map((p) => p.name));
        const line = lineOf(code, m.index);
        const evidence: Evidence[] = [{ source: `${file}:${line}`, detail: `FastAPI @${receiver}.${verb} route decorator.` }];
        if (!resolved) evidence.push({ source: `${file}:${line}`, detail: 'Router prefix or route path is not statically resolvable; path recorded as unknown.' });
        if (chain.deps.length > 0) evidence.push({ source: `${file}:${line}`, detail: `Inherited router/app dependencies: ${chain.deps.join(', ')}.` });

        for (const method of listMethods(args, verb)) {
          entries.push(
            buildEntry({
              framework: 'fastapi',
              method,
              path: fullPath,
              pathResolved: resolved,
              file,
              line,
              endLine: lineOf(code, def.sigClose),
              handler: def.name,
              controller: 'unknown',
              router: receiver,
              middleware: [],
              dependencies: unique([...routeLevelDeps, ...signature.deps]),
              parameters: pathParams,
              queryParameters: signature.query.filter((p) => !pathNames.has(p.name)),
              bodyParameters: signature.body.filter((p) => !pathNames.has(p.name)),
              extraAuth: unique([...signature.auth, ...routeLevelDeps.filter((d) => AUTHN_DEP_RE.test(d))]),
              extraAuthz: unique([...signature.authz, ...routeLevelDeps.filter((d) => AUTHZ_DEP_RE.test(d))]),
              uploadIndicators: signature.uploads.map((u) => `parameter: ${u}`),
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
