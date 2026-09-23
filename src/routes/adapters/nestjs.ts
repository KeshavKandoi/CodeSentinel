import type { Confidence, Evidence } from '../../discovery/types.js';
import { detectUploadIndicators, inlineAuthIndicators } from '../authHeuristics.js';
import { buildEntry, unique } from '../entryFactory.js';
import {
  buildLineIndex,
  collectConstStrings,
  evalPathString,
  extractRequestUsage,
  extractResponseIndicators,
  findMatching,
  lineAtIndex,
  stripJsComments,
  truncate,
} from '../jsScanner.js';
import { dedupeParams, expressPathParams, joinRoutePath, makeParam, toHttpMethod } from '../pathUtils.js';
import type { AdapterContext, AttackSurfaceEntry, FrameworkAdapter, HttpMethod, RouteParameter } from '../types.js';

const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'] as const;
const NEST_SOURCE_RE = /from\s+['"]@nestjs\/common['"]|require\s*\(\s*['"]@nestjs\/common['"]\s*\)|@(Controller|Get|Post|Put|Patch|Delete|UseGuards|UseInterceptors)\s*\(/;

const DECORATOR_TO_METHOD = new Map<string, HttpMethod>([
  ['Get', 'GET'],
  ['Post', 'POST'],
  ['Put', 'PUT'],
  ['Patch', 'PATCH'],
  ['Delete', 'DELETE'],
  ['All', 'ALL'],
  ['Head', 'HEAD'],
  ['Options', 'OPTIONS'],
]);

function splitTopLevel(text: string): string[] {
  const wrapped = `(${text})`;
  const parsed = /^/.exec(wrapped);
  void parsed;
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      i++;
      while (i < text.length && text.charAt(i) !== quote) {
        if (text.charAt(i) === '\\') i++;
        i++;
      }
    } else if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (c === ',' && depth === 0) {
      out.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  const tail = text.slice(start).trim();
  if (tail) out.push(tail);
  return out;
}

function stringArg(text: string, consts: ReadonlyMap<string, string>): string | null {
  const first = splitTopLevel(text)[0] ?? '';
  if (first === '') return '';
  return evalPathString(first, consts);
}

function guardNames(argsText: string): string[] {
  return splitTopLevel(argsText).map((x) => x.trim()).filter(Boolean);
}

function requestDecoratorParams(decorators: string, kind: 'Param' | 'Query' | 'Body'): RouteParameter[] {
  const out: RouteParameter[] = [];
  const re = new RegExp(`@${kind}\\s*\\(([^)]*)\\)`, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(decorators)) !== null) {
    const raw = (m[1] ?? '').trim();
    const lit = /^['"`]([^'"`]+)['"`]/.exec(raw);
    out.push(makeParam(lit?.[1] ?? `(entire ${kind.toLowerCase()})`));
  }
  return out;
}

interface Decorator {
  name: string;
  args: string;
  start: number;
  end: number;
}

interface DecoratorRun {
  decorators: Decorator[];
  start: number;
  end: number;
}

interface Controller {
  name: string;
  prefixArg: string;
  guards: string[];
  open: number;
  close: number;
  index: number;
}

const CLASS_DECL_RE = /^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/;
const METHOD_DECL_RE = /^\s*(?:(?:public|private|protected|static|async|override|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(/;

function decoratorRuns(code: string): DecoratorRun[] {
  const runs: DecoratorRun[] = [];
  const re = /(?<![\w$])@([A-Za-z_$][\w$]*)/g;
  let current: DecoratorRun | null = null;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const nameEnd = m.index + m[0].length;
    let end = nameEnd;
    let args = '';
    const paren = /^\s*\(/.exec(code.slice(nameEnd, nameEnd + 40));
    if (paren) {
      const open = nameEnd + paren[0].length - 1;
      const close = findMatching(code, open);
      if (close === -1) {
        current = null;
        continue;
      }
      args = code.slice(open + 1, close).trim();
      end = close + 1;
    }
    const decorator: Decorator = { name: m[1] ?? '', args, start: m.index, end };
    if (current !== null && decorator.start - current.end < 200 && /^\s*$/.test(code.slice(current.end, decorator.start))) {
      current.decorators.push(decorator);
      current.end = end;
    } else {
      current = { decorators: [decorator], start: decorator.start, end };
      runs.push(current);
    }
    re.lastIndex = end;
  }
  return runs;
}

function findControllers(code: string, runs: readonly DecoratorRun[]): Controller[] {
  const out: Controller[] = [];
  for (const run of runs) {
    const controller = run.decorators.find((d) => d.name === 'Controller');
    if (!controller) continue;
    const decl = CLASS_DECL_RE.exec(code.slice(run.end, run.end + 200));
    if (!decl) continue;
    const open = code.indexOf('{', run.end + decl[0].length);
    if (open === -1) continue;
    out.push({
      name: decl[1] ?? 'unknown',
      prefixArg: controller.args,
      guards: run.decorators.filter((d) => d.name === 'UseGuards').flatMap((d) => guardNames(d.args)),
      open,
      close: findMatching(code, open),
      index: run.start,
    });
  }
  return out;
}

export const nestjsAdapter: FrameworkAdapter = {
  id: 'nestjs',
  ecosystems: ['node'],

  appliesTo(ctx: AdapterContext): boolean {
    if (ctx.profile.ecosystem !== 'node') return false;
    const profileHit =
      ctx.profile.dependencies.some((d) => d.name === '@nestjs/common' || d.name === '@nestjs/core') ||
      ctx.profile.frameworks.backend.some((f) => f.name.toLowerCase() === 'nestjs');
    if (!profileHit) return false;
    return ctx.listSourceFiles(JS_EXTS).some((file) => {
      const src = ctx.readSource(file);
      return src !== null && NEST_SOURCE_RE.test(src.content);
    });
  },

  discover(ctx: AdapterContext): AttackSurfaceEntry[] {
    const entries: AttackSurfaceEntry[] = [];
    for (const file of ctx.listSourceFiles(JS_EXTS)) {
      const src = ctx.readSource(file);
      if (!src) continue;
      const code = stripJsComments(src.content);
      if (!NEST_SOURCE_RE.test(code)) continue;
      const lineStarts = buildLineIndex(code);
      const consts = collectConstStrings(code);
      const runs = decoratorRuns(code);

      for (const controller of findControllers(code, runs)) {
        if (controller.close === -1) {
          ctx.warnings.push(`${file}:${lineAtIndex(lineStarts, controller.index)}: could not parse NestJS controller class body; skipped.`);
          continue;
        }
        const prefix = stringArg(controller.prefixArg, consts);
        let lastEnd = controller.open;

        for (const run of runs) {
          if (run.start <= controller.open || run.end >= controller.close || run.start < lastEnd) continue;
          const routeDecs = run.decorators.filter((d) => DECORATOR_TO_METHOD.has(d.name));
          if (routeDecs.length === 0) continue;
          const decl = METHOD_DECL_RE.exec(code.slice(run.end, run.end + 200));
          if (!decl) continue;
          const paramsOpen = run.end + decl[0].length - 1;
          const paramsClose = findMatching(code, paramsOpen);
          if (paramsClose === -1) continue;
          const tail = code.slice(paramsClose + 1, paramsClose + 400);
          const braceRel = tail.indexOf('{');
          const semiRel = tail.indexOf(';');
          if (braceRel === -1 || (semiRel !== -1 && semiRel < braceRel)) continue;
          const bodyOpen = paramsClose + 1 + braceRel;
          const bodyClose = findMatching(code, bodyOpen);
          const endIdx = bodyClose === -1 ? paramsClose : bodyClose;
          lastEnd = endIdx + 1;

          const signature = code.slice(run.start, paramsClose + 1);
          const body = code.slice(run.start, endIdx + 1);
          const inline = inlineAuthIndicators(body);
          const methodGuards = run.decorators.filter((d) => d.name === 'UseGuards').flatMap((d) => guardNames(d.args));
          const interceptors = run.decorators.filter((d) => d.name === 'UseInterceptors').flatMap((d) => guardNames(d.args));
          const middleware = unique([...controller.guards, ...methodGuards, ...interceptors]);
          const usage = extractRequestUsage(body);
          const line = lineAtIndex(lineStarts, run.start);

          for (const routeDec of routeDecs) {
            const method = DECORATOR_TO_METHOD.get(routeDec.name) ?? toHttpMethod(routeDec.name);
            const routePath = stringArg(routeDec.args, consts);
            const resolved = prefix !== null && routePath !== null;
            const fullPath = resolved ? joinRoutePath(prefix ?? '', routePath ?? '') : 'unknown';
            const evidence: Evidence[] = [
              { source: `${file}:${line}`, detail: `NestJS @${routeDec.name} route in controller ${controller.name}.` },
            ];
            if (!resolved) evidence.push({ source: `${file}:${line}`, detail: 'Controller prefix or method path is not statically resolvable; path recorded as unknown.' });

            entries.push(
              buildEntry({
                framework: 'nestjs',
                method,
                path: fullPath,
                pathResolved: resolved,
                file,
                line,
                endLine: lineAtIndex(lineStarts, endIdx),
                handler: decl[1] ?? 'unknown',
                controller: controller.name,
                router: controller.name,
                middleware,
                dependencies: middleware,
                parameters: dedupeParams([...expressPathParams(fullPath), ...requestDecoratorParams(signature, 'Param')]),
                queryParameters: dedupeParams([...requestDecoratorParams(signature, 'Query'), ...usage.query.map((n) => makeParam(n))]),
                bodyParameters: dedupeParams([...requestDecoratorParams(signature, 'Body'), ...usage.body.map((n) => makeParam(n))]),
                extraAuth: inline.authn,
                extraAuthz: inline.authz,
                uploadIndicators: detectUploadIndicators(middleware, body),
                responseIndicators: extractResponseIndicators(body),
                confidence: resolved ? 'high' : 'low',
                evidence,
              })
            );
          }
        }
      }
    }
    return entries;
  },
};
