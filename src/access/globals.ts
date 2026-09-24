import { joinRoutePath, pathStartsWith } from '../routes/pathUtils.js';
import { matchClose, splitTopLevel } from '../routes/pyScanner.js';
import type { RouteFramework } from '../routes/types.js';
import { escapeRegExp, lineAtOffset } from './text.js';
import type { SourceResolver } from './text.js';
import type { AuthMechanism } from './types.js';

export type GlobalKind = 'guard' | 'middleware' | 'dependency' | 'default_permission' | 'default_authentication' | 'edge_middleware';

export interface GlobalGuard {
  name: string;
  base: string;
  kind: GlobalKind;
  framework: RouteFramework;
  file: string;
  line: number;
  mechanism: AuthMechanism | null;
  matches: (routePath: string) => boolean;
}

const ALWAYS = (): boolean => true;
const APP_VAR_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(express|[Ff]astify|NestFactory\s*\.\s*create)\s*(?:<[^>()]*>)?\s*\(/g;
const PROVIDER_RE = /provide\s*:\s*APP_GUARD\s*,\s*use(?:Class|Existing)\s*:\s*([A-Za-z_$][\w$]*)|use(?:Class|Existing)\s*:\s*([A-Za-z_$][\w$]*)\s*,\s*provide\s*:\s*APP_GUARD/g;
const NEXT_MW_FILE_RE = /^(?:src\/)?middleware\.(?:ts|js|mjs)$/;
const NEXT_AUTH_RE = /\b(?:getToken|withAuth|clerkMiddleware|authMiddleware|NextAuth|getSession|jwtVerify|verifyToken|auth)\s*\(|next-auth|@clerk|jsonwebtoken|from\s+['"]jose['"]|@supabase\//;

function callArgs(code: string, openIdx: number): string[] | null {
  const close = matchClose(code, openIdx);
  if (close === -1) return null;
  return splitTopLevel(code.slice(openIdx + 1, close));
}

function isPathArg(arg: string): boolean {
  return /^['"`/]/.test(arg.trim());
}

function argBase(arg: string): string | null {
  const m = /^(?:new\s+)?([A-Za-z_$][\w$.]*)/.exec(arg.trim());
  return m ? (m[1] ?? null) : null;
}

function pushGuards(out: GlobalGuard[], args: readonly string[], kind: GlobalKind, framework: RouteFramework, file: string, line: number): void {
  for (const arg of args) {
    const trimmed = arg.trim();
    if (trimmed === '' || /^['"`/]/.test(trimmed) || /=>|^(?:async\s+)?function\b|^async\b/.test(trimmed)) continue;
    const base = argBase(trimmed);
    if (!base) continue;
    out.push({ name: trimmed, base, kind, framework, file, line, mechanism: null, matches: ALWAYS });
  }
}

function jsGlobals(file: string, code: string, out: GlobalGuard[]): void {
  const appRe = new RegExp(APP_VAR_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = appRe.exec(code)) !== null) {
    const variable = m[1] ?? '';
    const ctor = m[2] ?? '';
    const framework: RouteFramework = /express/.test(ctor) ? 'express' : /astify/i.test(ctor) ? 'fastify' : 'nestjs';
    const method = framework === 'express' ? 'use' : framework === 'fastify' ? 'addHook' : 'useGlobalGuards';
    const callRe = new RegExp(`\\b${escapeRegExp(variable)}\\s*\\.\\s*${method}\\s*\\(`, 'g');
    let c: RegExpExecArray | null;
    while ((c = callRe.exec(code)) !== null) {
      const args = callArgs(code, c.index + c[0].length - 1);
      if (!args || args.length === 0) continue;
      const line = lineAtOffset(code, c.index, 1);
      if (framework === 'express') {
        if (isPathArg(args[0] ?? '')) continue;
        pushGuards(out, args, 'middleware', framework, file, line);
      } else if (framework === 'fastify') {
        if (!/^['"](?:onRequest|preHandler|preValidation|preParsing)['"]$/.test((args[0] ?? '').trim())) continue;
        pushGuards(out, args.slice(1), 'middleware', framework, file, line);
      } else {
        pushGuards(out, args, 'guard', framework, file, line);
      }
    }
  }
  const providerRe = new RegExp(PROVIDER_RE.source, 'g');
  while ((m = providerRe.exec(code)) !== null) {
    const name = m[1] ?? m[2] ?? '';
    if (name === '') continue;
    out.push({ name, base: name, kind: 'guard', framework: 'nestjs', file, line: lineAtOffset(code, m.index, 1), mechanism: null, matches: ALWAYS });
  }
}

function pyGlobals(file: string, code: string, out: GlobalGuard[]): void {
  const fastapi = /\b[A-Za-z_]\w*\s*=\s*FastAPI\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = fastapi.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(code, open);
    if (close === -1) continue;
    const args = code.slice(open + 1, close);
    const dep = /\bdependencies\s*=\s*\[/.exec(args);
    if (!dep) continue;
    const bracketOpen = dep.index + dep[0].length - 1;
    const bracketClose = matchClose(args, bracketOpen);
    const inner = args.slice(bracketOpen + 1, bracketClose === -1 ? args.length : bracketClose);
    const depRe = /\b(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)/g;
    let d: RegExpExecArray | null;
    while ((d = depRe.exec(inner)) !== null) {
      const name = d[1] ?? '';
      out.push({ name, base: name, kind: 'dependency', framework: 'fastapi', file, line: lineAtOffset(code, m.index, 1), mechanism: null, matches: ALWAYS });
    }
  }
  const rest = /\bREST_FRAMEWORK\s*=\s*\{/g;
  while ((m = rest.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(code, open);
    if (close === -1) continue;
    const body = code.slice(open, close + 1);
    const listRe = /['"]DEFAULT_(PERMISSION|AUTHENTICATION)_CLASSES['"]\s*:\s*[\[(]([^\])]*)[\])]/g;
    let d: RegExpExecArray | null;
    while ((d = listRe.exec(body)) !== null) {
      const kind: GlobalKind = d[1] === 'PERMISSION' ? 'default_permission' : 'default_authentication';
      const literal = /['"]([\w.]+)['"]/g;
      let s: RegExpExecArray | null;
      while ((s = literal.exec(d[2] ?? '')) !== null) {
        const name = s[1] ?? '';
        const base = name.split('.').pop() ?? name;
        out.push({ name, base, kind, framework: 'django', file, line: lineAtOffset(code, open + d.index, 1), mechanism: null, matches: ALWAYS });
      }
    }
  }
}

function nextMatcher(patterns: readonly string[] | null): (routePath: string) => boolean {
  if (!patterns || patterns.length === 0) return ALWAYS;
  const tests = patterns.map((raw): ((routePath: string) => boolean) => {
    if (raw.includes('(')) return ALWAYS;
    const stripped = raw.replace(/\/?:[A-Za-z_]\w*[*+?]?$/, '');
    const prefix = stripped === '' ? '/' : stripped;
    if (stripped !== raw) return (routePath) => pathStartsWith(routePath, prefix);
    return (routePath) => joinRoutePath(routePath) === joinRoutePath(prefix);
  });
  return (routePath) => tests.some((t) => t(routePath));
}

function nextGlobals(file: string, code: string, out: GlobalGuard[]): void {
  if (!NEXT_MW_FILE_RE.test(file) || !/next\/server|NextResponse|NextRequest/.test(code) || !NEXT_AUTH_RE.test(code)) return;
  let mechanism: AuthMechanism = 'session';
  if (/getToken|withAuth|NextAuth|next-auth|clerk|auth0|supabase/i.test(code)) mechanism = 'oauth';
  else if (/jwt|jose|verifyToken/i.test(code)) mechanism = 'jwt';
  const matcher = /\bmatcher\s*:\s*(\[[^\]]*\]|'[^']*'|"[^"]*")/.exec(code);
  const patterns = matcher ? Array.from((matcher[1] ?? '').matchAll(/['"]([^'"]+)['"]/g)).map((x) => x[1] ?? '') : null;
  out.push({
    name: 'middleware',
    base: 'middleware',
    kind: 'edge_middleware',
    framework: 'nextjs',
    file,
    line: lineAtOffset(code, matcher?.index ?? 0, 1),
    mechanism,
    matches: nextMatcher(patterns),
  });
}

export function collectGlobalGuards(resolver: SourceResolver): GlobalGuard[] {
  const out: GlobalGuard[] = [];
  for (const file of resolver.sourceFiles()) {
    const src = resolver.fileSource(file);
    if (!src) continue;
    if (src.python) {
      pyGlobals(file, src.code, out);
    } else {
      jsGlobals(file, src.code, out);
      nextGlobals(file, src.code, out);
    }
  }
  return out;
}
