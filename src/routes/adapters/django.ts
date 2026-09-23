import type { Evidence } from '../../discovery/types.js';
import { buildEntry, unique } from '../entryFactory.js';
import { dedupeParams, makeParam, toHttpMethod } from '../pathUtils.js';
import { blankRanges, insideRange, lineOf, matchClose, scanPython, splitTopLevel } from '../pyScanner.js';
import type { StringRange } from '../pyScanner.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const PY_EXTS = ['.py'] as const;
const DJANGO_RE = /\bfrom\s+django\.urls\s+import\b|\burlpatterns\s*=|\bpath\s*\(|\bre_path\s*\(|\binclude\s*\(|\brest_framework\b/;
const URLCONF_RE = /\burlpatterns\s*(?:=|\+=)|\bfrom\s+django\.(?:urls|conf\.urls)\s+import\b/;
const ROUTE_START_RE = /(?<![\w.])(path|re_path)\s*\(/g;
const INCLUDE_ARG_RE = /^include\s*\(\s*(?:\(\s*)?(['"])(.*?)\1/;
const AUTH_RE = /\b(?:login_required|LoginRequiredMixin|permission_required|PermissionRequiredMixin|authentication_classes|IsAuthenticated|IsAuthenticatedOrReadOnly|TokenAuthentication|SessionAuthentication|JWTAuthentication|BasicAuthentication|staff_member_required)\b/;
const AUTHZ_RE = /\b(?:user_passes_test|UserPassesTestMixin|permission_required|PermissionRequiredMixin|IsAdminUser|DjangoModelPermissions|DjangoObjectPermissions|IsOwner|has_perms?|is_staff|is_superuser|staff_member_required)\b/;

interface PyFile {
  file: string;
  moduleName: string;
  code: string;
  ranges: StringRange[];
  codeLines: string[];
  blankedLines: string[];
}

interface IncludeEdge {
  target: string;
  prefix: string;
  from: string;
}

interface ViewInfo {
  auth: string[];
  authz: string[];
  methods: HttpMethod[];
  uploads: string[];
}

function normalizeDjangoPath(raw: string): { path: string; params: RouteParameter[] } {
  const params: RouteParameter[] = [];
  let path = raw.replace(/^\^/, '').replace(/\$$/, '');
  path = path.replace(/\(\?P<(\w+)>[^)]+\)/g, (_all, name: string) => {
    params.push(makeParam(name));
    return `:${name}`;
  });
  path = path.replace(/<(?:(\w+):)?(\w+)>/g, (_all, type: string | undefined, name: string) => {
    params.push(makeParam(name, type ?? 'string'));
    return `:${name}`;
  });
  path = '/' + path.replace(/^\/+|\/+$/g, '');
  return { path, params: dedupeParams(params) };
}

function joinPath(a: string, b: string): string {
  return '/' + [a, b].flatMap((p) => p.split('/')).filter(Boolean).join('/');
}

function literalOf(text: string | undefined): string | null {
  if (!text) return null;
  const m = /^[rRuUbBfF]{0,2}(['"])([\s\S]*)\1$/.exec(text.trim());
  return m ? (m[2] ?? '') : null;
}

function unwrapView(expr: string): { handler: string; wrappers: string[] } {
  let current = expr.trim();
  const wrappers: string[] = [];
  for (let depth = 0; depth < 5; depth++) {
    const asView = /^([A-Za-z_][\w.]*?)\.as_view\s*\(/.exec(current);
    if (asView) return { handler: asView[1] ?? current, wrappers };
    const call = /^([A-Za-z_][\w.]*)\s*\(/.exec(current);
    if (!call) break;
    const open = current.indexOf('(');
    const close = matchClose(current, open);
    if (close === -1 || close !== current.length - 1) break;
    wrappers.push(call[1] ?? '');
    current = splitTopLevel(current.slice(open + 1, close))[0] ?? '';
  }
  return { handler: current, wrappers };
}

function loadFiles(ctx: AdapterContext): PyFile[] {
  const out: PyFile[] = [];
  for (const file of ctx.listSourceFiles(PY_EXTS)) {
    const src = ctx.readSource(file);
    if (!src) continue;
    const scanned = scanPython(src.content);
    const blanked = blankRanges(scanned.code, scanned.ranges);
    out.push({
      file,
      moduleName: file.replace(/\.py$/, '').replace(/\//g, '.'),
      code: scanned.code,
      ranges: scanned.ranges,
      codeLines: scanned.code.split('\n'),
      blankedLines: blanked.split('\n'),
    });
  }
  return out;
}

function collectEdges(files: readonly PyFile[]): IncludeEdge[] {
  const edges: IncludeEdge[] = [];
  for (const f of files) {
    if (!URLCONF_RE.test(f.code)) continue;
    const re = new RegExp(ROUTE_START_RE.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(f.code)) !== null) {
      if (insideRange(f.ranges, m.index)) continue;
      const open = m.index + m[0].length - 1;
      const close = matchClose(f.code, open);
      if (close === -1) continue;
      const parts = splitTopLevel(f.code.slice(open + 1, close));
      const rawPath = literalOf(parts[0]);
      const include = INCLUDE_ARG_RE.exec((parts[1] ?? '').trim());
      if (rawPath === null || !include) continue;
      edges.push({ target: include[2] ?? '', prefix: normalizeDjangoPath(rawPath).path, from: f.moduleName });
    }
  }
  return edges;
}

function prefixFor(moduleName: string, edges: readonly IncludeEdge[], seen: Set<string>): string {
  if (seen.has(moduleName) || seen.size > 8) return '';
  seen.add(moduleName);
  const edge = edges.find((e) => moduleName === e.target || moduleName.endsWith(`.${e.target}`));
  if (!edge) return '';
  return joinPath(prefixFor(edge.from, edges, seen), edge.prefix);
}

function definitionRange(lines: readonly string[], name: string): { start: number; end: number } | null {
  const re = new RegExp(`^(\\s*)(?:async\\s+def|def|class)\\s+${name}\\b`);
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i] ?? '');
    if (!m) continue;
    const indent = (m[1] ?? '').length;
    let start = i;
    let balance = 0;
    for (let k = i - 1; k >= 0 && i - k <= 40; k--) {
      const line = lines[k] ?? '';
      const trimmed = line.trim();
      if (trimmed === '') break;
      for (const ch of line) {
        if (ch === ')' || ch === ']') balance++;
        else if (ch === '(' || ch === '[') balance--;
      }
      if (balance > 0 || trimmed.startsWith('@')) {
        start = k;
        continue;
      }
      break;
    }
    let end = i;
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j] ?? '';
      if (line.trim() === '') continue;
      if (line.length - line.trimStart().length <= indent) break;
      end = j;
    }
    return { start, end };
  }
  return null;
}

function detectMethods(raw: string, blanked: string): HttpMethod[] {
  const out = new Set<HttpMethod>();
  for (const verb of ['get', 'post', 'put', 'patch', 'delete'] as const) {
    if (new RegExp(`\\bdef\\s+${verb}\\s*\\(`).test(blanked)) out.add(toHttpMethod(verb));
  }
  const listed = /@(?:api_view|require_http_methods)\s*\(\s*\[([^\]]*)\]/.exec(raw);
  if (listed) {
    const re = /['"]([A-Za-z]+)['"]/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(listed[1] ?? '')) !== null) out.add(toHttpMethod(m[1] ?? ''));
  }
  if (/@require_GET\b/.test(blanked)) out.add('GET');
  if (/@require_POST\b/.test(blanked)) out.add('POST');
  return Array.from(out);
}

function analyzeView(files: readonly PyFile[], handler: string, wrappers: readonly string[], urlFile: string): ViewInfo {
  const parts = handler.split('.');
  const name = parts[parts.length - 1] ?? '';
  const qualifier = parts.length > 1 ? (parts[parts.length - 2] ?? '') : '';
  let raw = '';
  let blanked = '';
  if (/^[A-Za-z_]\w*$/.test(name)) {
    const candidates: Array<{ file: PyFile; start: number; end: number }> = [];
    for (const f of files) {
      const range = definitionRange(f.blankedLines, name);
      if (range) candidates.push({ file: f, ...range });
    }
    const baseOf = (file: string): string => file.slice(file.lastIndexOf('/') + 1).replace(/\.py$/, '');
    const chosen =
      candidates.find((c) => qualifier !== '' && baseOf(c.file.file) === qualifier) ??
      candidates.find((c) => c.file.file === urlFile) ??
      candidates[0];
    if (chosen) {
      raw = chosen.file.codeLines.slice(chosen.start, chosen.end + 1).join('\n');
      blanked = chosen.file.blankedLines.slice(chosen.start, chosen.end + 1).join('\n');
    }
  }
  const text = `${blanked}\n${wrappers.join(' ')}`;
  const perm = /permission_classes\s*(?:=|\()\s*[\[(]([^\])]*)[\])]/.exec(text);
  const permNames = perm ? (perm[1] ?? '').split(',').map((s) => s.trim().split('.').pop() ?? '').filter(Boolean) : [];
  const publicByPermission = permNames.length > 0 && permNames.every((n) => n === 'AllowAny');
  const auth: string[] = [];
  const authz: string[] = [];
  const uploads: string[] = [];
  if (publicByPermission ? /\b(?:login_required|LoginRequiredMixin)\b/.test(text) : AUTH_RE.test(text)) auth.push('view auth decorator/class');
  const restrictive = permNames.some((n) => !['AllowAny', 'IsAuthenticated', 'IsAuthenticatedOrReadOnly'].includes(n));
  if (AUTHZ_RE.test(text) || restrictive) authz.push('view permission indicator');
  if (/request\.FILES|FileField|MultiPartParser|FormParser/i.test(blanked)) uploads.push('view file upload indicator');
  return { auth: unique(auth), authz: unique(authz), methods: detectMethods(raw, blanked), uploads: unique(uploads) };
}

export const djangoAdapter: FrameworkAdapter = {
  id: 'django',
  ecosystems: ['python'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'python') return false;
    return ctx.listSourceFiles(PY_EXTS).some((file) => {
      const src = ctx.readSource(file);
      return src !== null && DJANGO_RE.test(scanPython(src.content).code);
    });
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const files = loadFiles(ctx);
    const edges = collectEdges(files);
    const entries: AttackSurfaceEntry[] = [];
    for (const f of files) {
      if (!URLCONF_RE.test(f.code)) continue;
      const prefix = prefixFor(f.moduleName, edges, new Set());
      const re = new RegExp(ROUTE_START_RE.source, 'g');
      let m: RegExpExecArray | null;
      while ((m = re.exec(f.code)) !== null) {
        if (insideRange(f.ranges, m.index)) continue;
        const open = m.index + m[0].length - 1;
        const close = matchClose(f.code, open);
        if (close === -1) continue;
        const parts = splitTopLevel(f.code.slice(open + 1, close));
        const rawPath = literalOf(parts[0]);
        const viewExpr = (parts[1] ?? '').trim();
        if (rawPath === null || viewExpr === '' || /^include\s*\(/.test(viewExpr)) continue;
        const normalized = normalizeDjangoPath(rawPath);
        const fullPath = joinPath(prefix, normalized.path);
        const view = unwrapView(viewExpr);
        const info = analyzeView(files, view.handler, view.wrappers, f.file);
        const methods = info.methods.length > 0 ? info.methods : ['ALL' as HttpMethod];
        const line = lineOf(f.code, m.index);
        const evidence: Evidence[] = [{ source: `${f.file}:${line}`, detail: `Django ${m[1]}() URL pattern.` }];
        if (prefix) evidence.push({ source: 'include-resolution', detail: `Resolved include() prefix "${prefix}" for module ${f.moduleName}.` });

        for (const method of methods) {
          entries.push(
            buildEntry({
              framework: 'django',
              method,
              path: fullPath,
              pathResolved: true,
              file: f.file,
              line,
              endLine: lineOf(f.code, close),
              handler: view.handler,
              controller: view.handler.includes('.') ? (view.handler.split('.')[0] ?? 'unknown') : 'unknown',
              router: 'urlpatterns',
              middleware: [],
              dependencies: [],
              parameters: normalized.params,
              queryParameters: [],
              bodyParameters: [],
              extraAuth: info.auth,
              extraAuthz: info.authz,
              uploadIndicators: info.uploads,
              responseIndicators: [],
              confidence: 'high',
              evidence,
            })
          );
        }
      }
    }
    return entries;
  },
};
