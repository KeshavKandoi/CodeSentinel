import type { AttackSurfaceEntry } from '../routes/types.js';
import { escapeRegExp, lineAtOffset } from './text.js';
import type { RouteSource, SourcePart } from './text.js';
import type { IdentityKind, IdentitySource } from './types.js';

const BASE_IDENTITIES: Record<string, string[]> = {
  express: ['req.user', 'req.session.user', 'req.auth', 'res.locals.user'],
  fastify: ['request.user', 'req.user', 'request.session.user', 'request.auth'],
  nestjs: ['req.user', 'request.user'],
  nextjs: [],
  fastapi: ['request.state.user', 'request.user'],
  django: ['request.user', 'self.request.user'],
};

const RESERVED = new Set([
  'req', 'request', 'res', 'reply', 'response', 'self', 'cls', 'db', 'ctx', 'next', 'this',
  'undefined', 'null', 'true', 'false', 'None', 'True', 'False',
]);
const USER_KEYS = /^(?:user|session|auth|principal|currentUser|claims|identity|userId|uid|sub)$/;
const PROVIDER_RE = /user|principal|identity|auth|token|claims|session|(?:^|[_-])me$/i;

interface IdentityRule {
  re: RegExp;
  kind: IdentityKind;
  names: (m: RegExpExecArray) => string[];
}

function destructured(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(',')) {
    const piece = raw.trim();
    if (piece === '') continue;
    const [keyPart, aliasPart] = piece.split(':');
    const key = (keyPart ?? '').trim();
    const alias = (aliasPart ?? keyPart ?? '').trim().replace(/\s*=.*$/, '');
    if (USER_KEYS.test(key)) out.push(alias);
  }
  return out;
}

const JS_RULES: IdentityRule[] = [
  {
    re: /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:req|request|ctx(?:\.state)?|res\.locals)\.(?:user|session|auth|jwtPayload|principal|claims)\b/g,
    kind: 'request_user',
    names: (m) => [m[1] ?? ''],
  },
  {
    re: /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:(?:req|request)(?![\w$.])|ctx\.state(?![\w$])|res\.locals(?![\w$]))/g,
    kind: 'request_user',
    names: (m) => destructured(m[1] ?? ''),
  },
  {
    re: /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:getServerSession|getSession|getToken|auth|currentUser|getCurrentUser|getAuthUser|verifyToken|jwt\.verify|jwt\.decode|jwtVerify|decodeToken|useSession)\s*\(/g,
    kind: 'session',
    names: (m) => [m[1] ?? ''],
  },
  {
    re: /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:getServerSession|getSession|getToken|auth|currentUser|getAuthUser|jwt\.verify|jwtVerify|useSession)\s*\(/g,
    kind: 'session',
    names: (m) => destructured(m[1] ?? ''),
  },
  {
    re: /@(?:CurrentUser|AuthUser|GetUser|ReqUser|User|Req|Request|Session|AuthenticatedUser|ActiveUser)\s*\([^)]*\)\s*([A-Za-z_$][\w$]*)/g,
    kind: 'decorator_param',
    names: (m) => [m[1] ?? ''],
  },
];

const PY_RULES: IdentityRule[] = [
  {
    re: /([A-Za-z_]\w*)\s*(?::\s*[A-Za-z_][\w.\[\], |]*)?\s*=\s*(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)/g,
    kind: 'dependency',
    names: (m) => (PROVIDER_RE.test(m[2] ?? '') ? [m[1] ?? ''] : []),
  },
  {
    re: /([A-Za-z_]\w*)\s*:\s*Annotated\s*\[[^\]]*?(?:Depends|Security)\s*\(\s*([A-Za-z_][\w.]*)/g,
    kind: 'dependency',
    names: (m) => (PROVIDER_RE.test(m[2] ?? '') ? [m[1] ?? ''] : []),
  },
  {
    re: /([A-Za-z_]\w*)\s*=\s*(?:self\.)?request\.user\b/g,
    kind: 'request_user',
    names: (m) => [m[1] ?? ''],
  },
];

function scanPart(part: SourcePart, python: boolean, add: (name: string, kind: IdentityKind, expression: string, part: SourcePart, line: number) => void): void {
  const rules = python ? PY_RULES : JS_RULES;
  for (const rule of rules) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(part.plain)) !== null) {
      const line = lineAtOffset(part.plain, m.index, part.startLine);
      const expression = m[0].replace(/\s+/g, ' ').slice(0, 120);
      for (const name of rule.names(m)) add(name, rule.kind, expression, part, line);
    }
  }
}

export function collectIdentitySources(entry: AttackSurfaceEntry, source: RouteSource): IdentitySource[] {
  const out: IdentitySource[] = [];
  const seen = new Set<string>();
  const add = (name: string, kind: IdentityKind, expression: string, part: SourcePart | null, line: number): void => {
    const clean = name.trim();
    if (clean === '' || RESERVED.has(clean) || !/^[A-Za-z_$][\w$.]*$/.test(clean) || seen.has(clean)) return;
    seen.add(clean);
    out.push({ kind, name: clean, expression, file: part?.file ?? entry.file, line, scope: 'handler' });
  };
  for (const base of BASE_IDENTITIES[entry.framework] ?? []) add(base, 'framework_user', base, null, entry.line);
  for (const part of source.parts) scanPart(part, part.file.endsWith('.py'), add);
  return out;
}

export function identityAlternation(sources: readonly IdentitySource[]): string {
  const names = Array.from(new Set(sources.map((s) => s.name))).sort((a, b) => b.length - a.length);
  return names.map(escapeRegExp).join('|');
}
