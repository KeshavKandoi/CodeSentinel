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
]);

function decoratorArgs(code: string, decorator: string, searchStart: number, searchEnd: number): Array<{ text: string; index: number }> {
  const out: Array<{ text: string; index: number }> = [];
  const re = new RegExp(`@${decorator}\\s*\\(`, 'g');
  re.lastIndex = searchStart;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null && m.index < searchEnd) {
    const open = code.indexOf('(', m.index);
    const close = findMatching(code, open);
    if (close === -1 || close > searchEnd + 500) continue;
    out.push({ text: code.slice(open + 1, close).trim(), index: m.index });
  }
  return out;
}

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

function methodName(decl: string): string {
  return /(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(/.exec(decl)?.[1] ?? 'unknown';
}

function methodEnd(code: string, openBraceSearchStart: number): number {
  const open = code.indexOf('{', openBraceSearchStart);
  if (open === -1) return openBraceSearchStart;
  const close = findMatching(code, open);
  return close === -1 ? openBraceSearchStart : close;
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

      const classRe = /((?:@\w+(?:\s*\([^)]*\))?\s*)*)\s*export\s+class\s+([A-Za-z_$][\w$]*)\s*|((?:@\w+(?:\s*\([^)]*\))?\s*)*)\s*class\s+([A-Za-z_$][\w$]*)\s*/g;
      let m: RegExpExecArray | null;
      while ((m = classRe.exec(code)) !== null) {
        const decoratorText = m[1] ?? m[3] ?? '';
        if (!/@Controller\s*\(/.test(decoratorText)) continue;
        const className = m[2] ?? m[4] ?? 'unknown';
        const classOpen = code.indexOf('{', m.index);
        if (classOpen === -1) continue;
        const classClose = findMatching(code, classOpen);
        if (classClose === -1) {
          ctx.warnings.push(`${file}:${lineAtIndex(lineStarts, m.index)}: could not parse NestJS controller class body; skipped.`);
          continue;
        }
        const controllerArg = decoratorArgs(decoratorText, 'Controller', 0, decoratorText.length)[0]?.text ?? '';
        const prefix = stringArg(controllerArg, consts);
        const classGuards = decoratorArgs(decoratorText, 'UseGuards', 0, decoratorText.length).flatMap((d) => guardNames(d.text));

        const methodRe = /((?:@\w+(?:\s*\([^)]*\))?\s*)+)\s*(?:public|private|protected)?\s*(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*(?::[^{;]+)?\{/g;
        methodRe.lastIndex = classOpen + 1;
        let mm: RegExpExecArray | null;
        while ((mm = methodRe.exec(code)) !== null && mm.index < classClose) {
          const decs = mm[1] ?? '';
          const routeDec = Array.from(DECORATOR_TO_METHOD.keys())
            .map((name) => ({ name, hit: decoratorArgs(decs, name, 0, decs.length)[0] }))
            .find((x) => x.hit !== undefined);
          if (!routeDec || !routeDec.hit) continue;
          const method = DECORATOR_TO_METHOD.get(routeDec.name) ?? toHttpMethod(routeDec.name);
          const routePath = stringArg(routeDec.hit.text, consts);
          const resolved = prefix !== null && routePath !== null;
          const fullPath = resolved ? joinRoutePath(prefix ?? '', routePath ?? '') : 'unknown';
          const endIdx = methodEnd(code, mm.index + mm[0].length - 1);
          const body = endIdx > mm.index ? code.slice(mm.index, endIdx + 1) : mm[0];
          const inline = inlineAuthIndicators(body);
          const methodGuards = decoratorArgs(decs, 'UseGuards', 0, decs.length).flatMap((d) => guardNames(d.text));
          const interceptors = decoratorArgs(decs, 'UseInterceptors', 0, decs.length).flatMap((d) => guardNames(d.text));
          const middleware = unique([...classGuards, ...methodGuards, ...interceptors]);
          const usage = extractRequestUsage(body);
          const evidence: Evidence[] = [
            { source: `${file}:${lineAtIndex(lineStarts, mm.index)}`, detail: `NestJS @${routeDec.name} route in controller ${className}.` },
          ];
          if (!resolved) evidence.push({ source: `${file}:${lineAtIndex(lineStarts, mm.index)}`, detail: 'Controller prefix or method path is not statically resolvable; path recorded as unknown.' });

          entries.push(
            buildEntry({
              framework: 'nestjs',
              method,
              path: fullPath,
              pathResolved: resolved,
              file,
              line: lineAtIndex(lineStarts, mm.index),
              endLine: lineAtIndex(lineStarts, endIdx),
              handler: methodName(mm[0]),
              controller: className,
              router: className,
              middleware,
              dependencies: middleware,
              parameters: dedupeParams([...expressPathParams(fullPath), ...requestDecoratorParams(decs + mm[0], 'Param')]),
              queryParameters: dedupeParams([...requestDecoratorParams(decs + mm[0], 'Query'), ...usage.query.map((n) => makeParam(n))]),
              bodyParameters: dedupeParams([...requestDecoratorParams(decs + mm[0], 'Body'), ...usage.body.map((n) => makeParam(n))]),
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
    return entries;
  },
};
