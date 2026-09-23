import type { Evidence } from '../../discovery/types.js';
import { buildEntry, unique } from '../entryFactory.js';
import { dedupeParams, makeParam } from '../pathUtils.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const PY_EXTS = ['.py'] as const;
const DJANGO_RE = /\bfrom\s+django\.urls\s+import\b|\burlpatterns\s*=|\bpath\s*\(|\bre_path\s*\(|\binclude\s*\(|\brest_framework\b/;

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

function normalizeDjangoPath(raw: string): { path: string; params: RouteParameter[] } {
  const params: RouteParameter[] = [];
  let path = raw.replace(/^\^/, '').replace(/\$$/, '');
  path = path.replace(/<(?:(\w+):)?(\w+)>/g, (_all, type: string | undefined, name: string) => {
    params.push(makeParam(name, type ?? 'string'));
    return `:${name}`;
  });
  path = path.replace(/\(\?P<(\w+)>[^)]+\)/g, (_all, name: string) => {
    params.push(makeParam(name));
    return `:${name}`;
  });
  path = '/' + path.replace(/^\/+|\/+$/g, '');
  return { path, params: dedupeParams(params) };
}

function joinPath(a: string, b: string): string {
  return '/' + [a, b].flatMap((p) => p.split('/')).filter(Boolean).join('/');
}

function viewName(raw: string): string {
  return raw.trim().replace(/\.as_view\s*\(\s*\)$/, '');
}

function viewIndicators(codeByFile: Map<string, string>, view: string): { auth: string[]; authz: string[]; methods: HttpMethod[]; uploads: string[] } {
  const auth: string[] = [];
  const authz: string[] = [];
  const uploads: string[] = [];
  const methods = new Set<HttpMethod>();
  const simple = view.split('.').pop() ?? view;
  for (const code of codeByFile.values()) {
    const idx = code.indexOf(`def ${simple}`);
    const classIdx = code.indexOf(`class ${simple}`);
    const start = idx >= 0 ? idx : classIdx;
    if (start < 0) continue;
    const before = code.slice(Math.max(0, start - 500), start);
    const body = code.slice(start, start + 2000);
    if (/login_required|permission_required|authentication_classes|IsAuthenticated|TokenAuthentication/i.test(before + body)) auth.push('view auth decorator/class');
    if (/user_passes_test|permission_classes|IsAdminUser|DjangoModelPermissions|has_perm|IsOwner/i.test(before + body)) authz.push('view permission indicator');
    if (/request\.FILES|FileField|MultiPartParser|FormParser/i.test(body)) uploads.push('view file upload indicator');
    for (const m of ['get', 'post', 'put', 'patch', 'delete'] as const) {
      if (new RegExp(`\\bdef\\s+${m}\\s*\\(`).test(body)) methods.add(m.toUpperCase() as HttpMethod);
    }
  }
  return { auth: unique(auth), authz: unique(authz), methods: Array.from(methods), uploads: unique(uploads) };
}

export const djangoAdapter: FrameworkAdapter = {
  id: 'django',
  ecosystems: ['python'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'python') return false;
    return ctx.listSourceFiles(PY_EXTS).some((file) => {
      const src = ctx.readSource(file);
      return src !== null && DJANGO_RE.test(stripPyComments(src.content));
    });
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const codeByFile = new Map<string, string>();
    for (const file of ctx.listSourceFiles(PY_EXTS)) {
      const src = ctx.readSource(file);
      if (src) codeByFile.set(file, stripPyComments(src.content));
    }

    const includes = new Map<string, string>();
    for (const [file, code] of codeByFile) {
      const includeRe = /path\s*\(\s*(['"])(.*?)\1\s*,\s*include\s*\(\s*(['"])(.*?)\3\s*\)/g;
      let im: RegExpExecArray | null;
      while ((im = includeRe.exec(code)) !== null) includes.set(im[4] ?? '', im[2] ?? '');
    }

    const entries: AttackSurfaceEntry[] = [];
    for (const [file, code] of codeByFile) {
      if (!DJANGO_RE.test(code)) continue;
      const moduleName = file.replace(/\.py$/, '').replace(/\//g, '.');
      const prefix = includes.get(moduleName) ?? '';
      const routeRe = /(path|re_path)\s*\(\s*(['"])(.*?)\2\s*,\s*([^,\n)]+(?:\.as_view\s*\(\s*\))?)/g;
      let m: RegExpExecArray | null;
      while ((m = routeRe.exec(code)) !== null) {
        const rawPath = m[3] ?? '';
        const rawView = m[4] ?? '';
        if (/include\s*\(/.test(rawView)) continue;
        const normalized = normalizeDjangoPath(rawPath);
        const fullPath = joinPath(prefix, normalized.path);
        const handler = viewName(rawView);
        const indicators = viewIndicators(codeByFile, handler);
        const methods = indicators.methods.length > 0 ? indicators.methods : ['ALL' as HttpMethod];
        const evidence: Evidence[] = [{ source: `${file}:${lineAt(code, m.index)}`, detail: `Django ${m[1]}() URL pattern.` }];
        if (prefix) evidence.push({ source: 'include-resolution', detail: `Resolved include() prefix "${prefix}" for module ${moduleName}.` });

        for (const method of methods) {
          entries.push(
            buildEntry({
              framework: 'django',
              method,
              path: fullPath,
              pathResolved: true,
              file,
              line: lineAt(code, m.index),
              endLine: lineAt(code, m.index),
              handler,
              controller: handler.includes('.') ? handler.split('.')[0] ?? 'unknown' : 'unknown',
              router: 'urlpatterns',
              middleware: [],
              dependencies: [],
              parameters: normalized.params,
              queryParameters: [],
              bodyParameters: [],
              extraAuth: indicators.auth,
              extraAuthz: indicators.authz,
              uploadIndicators: indicators.uploads,
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
