import { createHash } from 'node:crypto';
import type { Confidence } from '../discovery/types.js';
import { splitTopLevel } from '../routes/pyScanner.js';
import type { AttackSurfaceEntry, RouteFramework } from '../routes/types.js';
import type { GlobalGuard } from './globals.js';
import { DECISION_RE, ENFORCEMENT_RE, PUBLIC_MARKER_RE, REJECT_RE, classifyGuardName, requirementOf, splitCall } from './patterns.js';
import { decoratorStart, escapeRegExp, lineAtOffset, normalizePlain } from './text.js';
import type { RouteSource, SourceResolver } from './text.js';
import type {
  AuthControl,
  AuthMechanism,
  AuthorizationControl,
  AuthorizationKind,
  GuardAssessment,
  IdentitySource,
  ProtectionScope,
} from './types.js';

interface Loc {
  file: string;
  line: number;
}

interface Placement {
  scope: ProtectionScope;
  inherited: boolean;
  file: string;
  line: number;
}

export interface ControlShared {
  resolver: SourceResolver;
  globals: readonly GlobalGuard[];
  locations: Map<string, Loc | null>;
  assessments: Map<string, GuardAssessment>;
}

export interface PublicMarker {
  name: string;
  scope: ProtectionScope;
  inherited: boolean;
  file: string;
  line: number;
}

export interface EntryControls {
  authentication: AuthControl[];
  authorization: AuthorizationControl[];
  publicMarkers: PublicMarker[];
}

interface Ctx {
  entry: AttackSurfaceEntry;
  source: RouteSource;
  shared: ControlShared;
  identities: readonly IdentitySource[];
  authn: Map<string, AuthControl>;
  authz: Map<string, AuthorizationControl>;
  publicMarkers: PublicMarker[];
  overridesDefaultPermission: boolean;
}

interface AuthnInput {
  mechanism: AuthMechanism;
  name: string;
  place: Placement;
  confidence: Confidence;
  assessment?: GuardAssessment | null;
  detail: string;
}

interface AuthzInput {
  kind: AuthorizationKind;
  name: string;
  requirement: string | null;
  place: Placement;
  confidence: Confidence;
  assessment?: GuardAssessment | null;
  detail: string;
}

interface CallRule {
  re: RegExp;
  mechanism: AuthMechanism;
  label: string;
  lookup: boolean;
}

const IMPORT_LINE_RE = /^\s*(?:import\b|from\b|export\s+\{|(?:const|let|var)\s*\{[^}]*\}\s*=\s*require\b)/;
const MOUNT_LINE_RE = /\.\s*(?:use|register|addHook|include_router|useGlobalGuards)\s*\(|\bdependencies\s*=|@UseGuards\s*\(|\bAPIRouter\s*\(|\bFastAPI\s*\(|\bpreHandler\b|\bonRequest\b|APP_GUARD/;
const TRIVIAL_ALLOW_RE = /canActivate\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*return\s+true\s*;?\s*\}/;
const CALL_RE = /(?<![\w$.])([A-Za-z_$][\w$.]*)\s*\(/g;
const NOT_CALLS = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'async', 'await', 'def', 'class', 'next', 'super', 'typeof', 'print', 'len']);
const SCHEME_RE = /\b([A-Za-z_]\w*)\s*=\s*(HTTPBearer|HTTPDigest|HTTPBasic|OAuth2PasswordBearer|OAuth2AuthorizationCodeBearer|APIKeyHeader|APIKeyCookie|APIKeyQuery)\s*\(/g;
const DRF_RE = /\b(?:APIView|ViewSet|GenericAPIView|ModelViewSet|ReadOnlyModelViewSet|GenericViewSet|api_view|ListAPIView|RetrieveAPIView|CreateAPIView|UpdateAPIView|DestroyAPIView|ListCreateAPIView|RetrieveUpdateAPIView|RetrieveUpdateDestroyAPIView)\b/;

const NON_CONTROL_DECORATORS = new Set([
  'Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'All', 'Param', 'Query', 'Body', 'Headers', 'Req', 'Request', 'Res',
  'Response', 'Session', 'Ip', 'HostParam', 'UploadedFile', 'UploadedFiles', 'UseGuards', 'UseInterceptors', 'UsePipes', 'UseFilters',
  'Controller', 'Injectable', 'Module', 'HttpCode', 'Header', 'Redirect', 'Render', 'Sse', 'CurrentUser', 'AuthUser', 'GetUser', 'ReqUser',
  'User', 'ActiveUser', 'AuthenticatedUser',
]);

const CALL_RULES: CallRule[] = [
  {
    re: /\bjwt\s*\.\s*verify\s*\(|\bjwtVerify\s*\(|\bverifyJwt\s*\(|\bverify_jwt\w*\s*\(|\bverifyToken\s*\(|\bverify_token\s*\(|\bdecode_jwt\s*\(|\bvalidate_token\s*\(/,
    mechanism: 'jwt',
    label: 'token verification call',
    lookup: false,
  },
  { re: /\bjwt\s*\.\s*decode\s*\(/, mechanism: 'jwt', label: 'jwt.decode call', lookup: true },
  { re: /\bpassport\s*\.\s*authenticate\s*\(/, mechanism: 'passport', label: 'passport.authenticate call', lookup: false },
  { re: /\b(?:getServerSession|unstable_getServerSession|getSession|useSession)\s*\(/, mechanism: 'session', label: 'session lookup', lookup: true },
  { re: /\bgetToken\s*\(/, mechanism: 'oauth', label: 'getToken lookup', lookup: true },
  {
    re: /(?:=|\bawait|\breturn)\s*auth\s*\(\s*\)|\bcurrentUser\s*\(\s*\)|\bgetCurrentUser\s*\(|\bgetAuthUser\s*\(/,
    mechanism: 'session',
    label: 'current-user lookup',
    lookup: true,
  },
];

const VERIFY_RE = CALL_RULES[0]?.re ?? /$^/;
const BEARER_HEADER_RE = /\b(?:req|request)\s*\.\s*(?:headers?\s*(?:\.\s*authorization\b|\[\s*['"]authorization['"]\s*\]|\.\s*get\s*\(\s*['"]authorization['"])|(?:get|header)\s*\(\s*['"]authorization['"])|\bMETA\s*(?:\.\s*get\s*\(\s*|\[\s*)['"]HTTP_AUTHORIZATION['"]/i;
const API_KEY_HEADER_RE = /\b(?:req|request)\s*\.\s*(?:headers?\s*(?:\.\s*get\s*\(\s*|\[\s*)|(?:get|header)\s*\(\s*)['"]x-api-key['"]/i;
const PY_HEADER_PARAM_RE = /\bauthorization\s*:\s*[^=\n,)]*=\s*Header\s*\(/i;
const PROP_SRC = 'role|roles|permissions?|scopes?|isAdmin|is_admin|isStaff|is_staff|isSuperuser|is_superuser|isSuperAdmin|groups|userType|user_type|accessLevel|access_level';
const CALL_NAMES = 'hasPermissions?|checkPermissions?|hasRoles?|hasAnyRole|hasAllRoles|checkRole|can|cannot|authorize|authorise|ensurePermission|ensureRole|has_perms?|has_role|check_permission|require_permission|require_role|enforce|isAllowed|is_allowed|checkAccess|hasAccess|assertCan';

function shortId(prefix: string, seed: string): string {
  return `${prefix}-${createHash('sha256').update(seed).digest('hex').slice(0, 10)}`;
}

function wordRe(base: string): RegExp {
  return new RegExp(`(?<![\\w$.])${escapeRegExp(base)}(?![\\w$])`);
}

function ownScope(framework: RouteFramework): ProtectionScope {
  if (framework === 'nestjs') return 'decorator';
  if (framework === 'fastapi') return 'dependency';
  return 'middleware';
}

function inheritedScope(framework: RouteFramework): ProtectionScope {
  return framework === 'nestjs' ? 'controller' : 'router';
}

function delegatesToAccessLogic(plain: string, selfName: string): boolean {
  if (/\b(?:Depends|Security)\s*\(/.test(plain)) return true;
  if (/\.\s*authorization\b|\bcookies\b|\bsession\b|\btoken\b/i.test(plain)) return true;
  const re = new RegExp(CALL_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(plain)) !== null) {
    const callee = m[1] ?? '';
    const last = callee.split('.').pop() ?? callee;
    if (last === selfName || NOT_CALLS.has(last)) continue;
    const cls = classifyGuardName(callee);
    if (cls.authn !== null || cls.authz !== null) return true;
  }
  return false;
}

function assessGuard(shared: ControlShared, base: string, preferFile: string): GuardAssessment {
  const key = `${preferFile}|${base}`;
  const cached = shared.assessments.get(key);
  if (cached) return cached;
  let result: GuardAssessment = { resolved: false, enforces: null, file: null, line: null };
  if (!base.includes('.')) {
    const def = shared.resolver.findDefinition(base, preferFile);
    if (def) {
      const plain = normalizePlain(def.code, def.file.endsWith('.py'));
      let enforces: boolean | null;
      if (TRIVIAL_ALLOW_RE.test(plain)) enforces = false;
      else if (ENFORCEMENT_RE.test(plain)) enforces = true;
      else enforces = delegatesToAccessLogic(plain, base) ? null : false;
      result = { resolved: true, enforces, file: def.file, line: def.line };
    }
  }
  shared.assessments.set(key, result);
  return result;
}

function schemeMechanism(type: string): AuthMechanism {
  if (type === 'HTTPBearer') return 'bearer';
  if (type.startsWith('OAuth2')) return 'oauth';
  if (type.startsWith('APIKey')) return 'api_key';
  return 'basic';
}

function resolveScheme(shared: ControlShared, entry: AttackSurfaceEntry, base: string): AuthMechanism | null {
  const fs = shared.resolver.fileSource(entry.file);
  if (!fs || !fs.python) return null;
  const re = new RegExp(SCHEME_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(fs.plain)) !== null) {
    if (m[1] === base) return schemeMechanism(m[2] ?? '');
  }
  return null;
}

function findInParts(source: RouteSource, base: string): Loc | null {
  const re = wordRe(base);
  for (const part of source.parts) {
    if (part.role !== 'route') continue;
    const lines = part.code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i] ?? '')) return { file: part.file, line: part.startLine + i };
    }
  }
  return null;
}

function classDecorators(shared: ControlShared, entry: AttackSurfaceEntry): { text: string; startLine: number } | null {
  if (entry.framework !== 'nestjs' || entry.controller === 'unknown') return null;
  const fs = shared.resolver.fileSource(entry.file);
  if (!fs) return null;
  const lines = fs.code.split('\n');
  const re = new RegExp(`\\bclass\\s+${escapeRegExp(entry.controller)}\\b`);
  const idx = lines.findIndex((l) => re.test(l));
  if (idx < 0) return null;
  const start = decoratorStart(lines, idx);
  return { text: lines.slice(start, idx + 1).join('\n'), startLine: start + 1 };
}

function locateInherited(shared: ControlShared, entry: AttackSurfaceEntry, base: string): Loc | null {
  const re = wordRe(base);
  const defRe = new RegExp(`\\b(?:function|def|class)\\s+${escapeRegExp(base)}\\b|\\b(?:const|let|var)\\s+${escapeRegExp(base)}\\s*=`);
  const usable = (line: string): boolean => re.test(line) && MOUNT_LINE_RE.test(line) && !IMPORT_LINE_RE.test(line) && !defRe.test(line);
  const own = shared.resolver.fileSource(entry.file);
  if (own) {
    const lines = own.code.split('\n');
    for (let i = Math.min(entry.line - 1, lines.length) - 1; i >= 0; i--) {
      if (usable(lines[i] ?? '')) return { file: entry.file, line: i + 1 };
    }
  }
  const cached = shared.locations.get(base);
  if (cached !== undefined) return cached;
  let found: Loc | null = null;
  for (const file of shared.resolver.sourceFiles()) {
    const fs = shared.resolver.fileSource(file);
    if (!fs) continue;
    const idx = fs.code.split('\n').findIndex((l) => usable(l));
    if (idx >= 0) {
      found = { file, line: idx + 1 };
      break;
    }
  }
  shared.locations.set(base, found);
  return found;
}

function placeOf(ctx: Ctx, base: string): Placement {
  const { entry, shared } = ctx;
  const globalHit = shared.globals.find(
    (g) =>
      (g.kind === 'middleware' || g.kind === 'dependency' || g.kind === 'guard') &&
      g.base === base &&
      g.framework === entry.framework &&
      g.matches(entry.path)
  );
  if (globalHit) return { scope: 'global', inherited: true, file: globalHit.file, line: globalHit.line };
  const own = findInParts(ctx.source, base);
  if (own) return { scope: ownScope(entry.framework), inherited: false, file: own.file, line: own.line };
  const cls = classDecorators(shared, entry);
  if (cls) {
    const re = wordRe(base);
    const idx = cls.text.split('\n').findIndex((l) => re.test(l));
    if (idx >= 0) return { scope: 'controller', inherited: true, file: entry.file, line: cls.startLine + idx };
  }
  const found = locateInherited(shared, entry, base);
  return { scope: inheritedScope(entry.framework), inherited: true, file: found?.file ?? entry.file, line: found?.line ?? entry.line };
}

function note(assessment: GuardAssessment): string {
  if (!assessment.resolved) return 'its implementation is not part of the analyzed source';
  if (assessment.enforces === true) return 'its implementation contains visible enforcement logic';
  if (assessment.enforces === false) return 'its implementation shows no visible enforcement logic';
  return 'its implementation delegates to other access logic';
}

function describe(place: Placement): string {
  return place.inherited ? `inherited from the ${place.scope} level` : `declared at the ${place.scope} level`;
}

function guardConfidence(base: Confidence, assessment: GuardAssessment): Confidence {
  if (assessment.resolved && assessment.enforces === false) return 'low';
  if (assessment.resolved && assessment.enforces === true) return 'high';
  return base;
}

function addAuthn(ctx: Ctx, input: AuthnInput): void {
  const key = `${input.mechanism}|${input.name}|${input.place.scope}|${input.place.file}|${input.place.line}`;
  if (ctx.authn.has(key)) return;
  ctx.authn.set(key, {
    id: shortId('AUTHN', `${ctx.entry.id}|${key}`),
    mechanism: input.mechanism,
    name: input.name,
    scope: input.place.scope,
    inherited: input.place.inherited,
    file: input.place.file,
    line: input.place.line,
    confidence: input.confidence,
    assessment: input.assessment ?? null,
    evidence: [{ source: `${input.place.file}:${input.place.line}`, detail: input.detail }],
  });
}

function addAuthz(ctx: Ctx, input: AuthzInput): void {
  const key = `${input.kind}|${input.name}|${input.place.scope}|${input.place.file}|${input.place.line}`;
  if (ctx.authz.has(key)) return;
  ctx.authz.set(key, {
    id: shortId('AUTHZ', `${ctx.entry.id}|${key}`),
    kind: input.kind,
    name: input.name,
    requirement: input.requirement,
    scope: input.place.scope,
    inherited: input.place.inherited,
    file: input.place.file,
    line: input.place.line,
    confidence: input.confidence,
    assessment: input.assessment ?? null,
    evidence: [{ source: `${input.place.file}:${input.place.line}`, detail: input.detail }],
  });
}

function expandNames(raw: readonly string[]): string[] {
  const out: string[] = [];
  const visit = (name: string, depth: number): void => {
    const { base, args } = splitCall(name);
    if (depth < 3 && /(?:^|\.)auth$/i.test(base) && args !== null && /^\s*\[/.test(args)) {
      const inner = args.trim().replace(/^\[/, '').replace(/\]\s*(?:,[\s\S]*)?$/, '');
      for (const part of splitTopLevel(inner)) visit(part, depth + 1);
      return;
    }
    out.push(name);
  };
  for (const name of raw) visit(name, 0);
  return Array.from(new Set(out));
}

function namedControls(ctx: Ctx): void {
  const seen = new Set<string>();
  for (const name of expandNames([...ctx.entry.middleware, ...ctx.entry.dependencies])) {
    const cls = classifyGuardName(name);
    const key = `${cls.base}|${cls.args ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const last = cls.base.split('.').pop() ?? cls.base;
    if (PUBLIC_MARKER_RE.test(last)) {
      const place = placeOf(ctx, cls.base);
      ctx.publicMarkers.push({ name, scope: place.scope, inherited: place.inherited, file: place.file, line: place.line });
      continue;
    }
    let authn = cls.authn;
    const authz = cls.authz;
    if (authn === null && authz === null) authn = resolveScheme(ctx.shared, ctx.entry, cls.base);
    if (authn === null && authz === null) continue;
    const place = placeOf(ctx, cls.base);
    const assessment = assessGuard(ctx.shared, cls.base, ctx.entry.file);
    if (authn !== null) {
      addAuthn(ctx, {
        mechanism: authn,
        name,
        place,
        confidence: guardConfidence(authn === 'generic' ? 'medium' : 'high', assessment),
        assessment,
        detail: `Guard "${name}" is ${describe(place)} and is named like a ${authn} authentication control; ${note(assessment)}.`,
      });
    }
    if (authz !== null) {
      addAuthz(ctx, {
        kind: authz.kind,
        name,
        requirement: authz.requirement,
        place,
        confidence: guardConfidence(authz.requirement !== null ? 'high' : 'medium', assessment),
        assessment,
        detail: `Guard "${name}" is ${describe(place)} and is named like a ${authz.kind} authorization control; ${note(assessment)}.`,
      });
    }
  }
}

function decoratorControls(ctx: Ctx): void {
  const route = ctx.source.parts.find((p) => p.role === 'route');
  const cls = classDecorators(ctx.shared, ctx.entry);
  const targets: Array<{ text: string; startLine: number; scope: ProtectionScope; inherited: boolean; file: string }> = [];
  if (route) targets.push({ text: route.code, startLine: route.startLine, scope: 'decorator', inherited: false, file: route.file });
  if (cls) targets.push({ text: cls.text, startLine: cls.startLine, scope: 'controller', inherited: true, file: ctx.entry.file });
  const decoratorRe = /(?<![\w$])@([A-Za-z_$][\w$]*)\s*(?:\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\))?/g;
  for (const target of targets) {
    for (const m of target.text.matchAll(decoratorRe)) {
      const name = m[1] ?? '';
      const args = m[2] ?? '';
      if (NON_CONTROL_DECORATORS.has(name) || /^Api[A-Z]/.test(name)) continue;
      const place: Placement = {
        scope: target.scope,
        inherited: target.inherited,
        file: target.file,
        line: lineAtOffset(target.text, m.index ?? 0, target.startLine),
      };
      if (PUBLIC_MARKER_RE.test(name)) {
        ctx.publicMarkers.push({ name: `@${name}`, scope: place.scope, inherited: place.inherited, file: place.file, line: place.line });
        continue;
      }
      if (name === 'SetMetadata') {
        const key = /^\s*['"](roles?|permissions?|scopes?)['"]/i.exec(args);
        if (key) {
          const kind: AuthorizationKind = /^perm/i.test(key[1] ?? '') ? 'permission' : /^scope/i.test(key[1] ?? '') ? 'scope' : 'role';
          addAuthz(ctx, {
            kind,
            name: `@SetMetadata(${key[1]})`,
            requirement: requirementOf('SetMetadata', args.replace(/^\s*['"][^'"]+['"]\s*,?/, '')),
            place,
            confidence: 'medium',
            detail: `Metadata decorator ${describe(place)} declares ${kind} requirements that a guard is expected to enforce.`,
          });
        }
        continue;
      }
      const classified = classifyGuardName(`${name}(${args})`);
      let authz = classified.authz;
      if (classified.authn === null && authz === null) continue;
      if (authz === null && /\b(?:Role|Roles|UserRole|Permission|Permissions)\s*\./.test(args)) {
        authz = { kind: 'role', requirement: requirementOf(name, args) };
      }
      if (classified.authn !== null) {
        addAuthn(ctx, {
          mechanism: classified.authn,
          name: `@${name}`,
          place,
          confidence: classified.authn === 'generic' ? 'medium' : 'high',
          detail: `Decorator @${name} ${describe(place)} is named like a ${classified.authn} authentication control.`,
        });
      }
      if (authz !== null) {
        addAuthz(ctx, {
          kind: authz.kind,
          name: `@${name}`,
          requirement: authz.requirement,
          place,
          confidence: authz.requirement !== null ? 'high' : 'medium',
          detail: `Decorator @${name} ${describe(place)} declares ${authz.kind} requirements${authz.requirement ? ` (${authz.requirement})` : ''}.`,
        });
      }
    }
  }
}

function pythonControls(ctx: Ctx): void {
  for (const part of ctx.source.parts) {
    if (!part.file.endsWith('.py')) continue;
    const text = part.plain
      .split('\n')
      .map((l) => (/^\s*(?:from|import)\s/.test(l) ? ' '.repeat(l.length) : l))
      .join('\n');
    const at = (index: number): number => lineAtOffset(text, index, part.startLine);
    const argsAt = (index: number, fn: string): string => {
      const m = new RegExp(`${fn}\\s*\\(([^)]*)\\)`).exec(part.code.slice(index, index + 300));
      return m ? (m[1] ?? '') : '';
    };

    for (const m of text.matchAll(/(?<![\w.])(login_required|staff_member_required|superuser_required|permission_required|user_passes_test)\b/g)) {
      const fn = m[1] ?? '';
      const index = m.index ?? 0;
      const place: Placement = { scope: 'decorator', inherited: false, file: part.file, line: at(index) };
      if (fn === 'user_passes_test') {
        addAuthz(ctx, { kind: 'policy', name: fn, requirement: null, place, confidence: 'medium', detail: 'Django user_passes_test wrapper applies a custom access predicate.' });
        continue;
      }
      addAuthn(ctx, { mechanism: 'framework', name: fn, place, confidence: 'high', detail: `Django ${fn} wrapper requires an authenticated user.` });
      if (fn === 'staff_member_required') {
        addAuthz(ctx, { kind: 'role', name: fn, requirement: 'staff', place, confidence: 'high', detail: 'Django staff_member_required restricts the view to staff users.' });
      } else if (fn === 'superuser_required') {
        addAuthz(ctx, { kind: 'role', name: fn, requirement: 'superuser', place, confidence: 'medium', detail: 'superuser_required restricts the view to superusers.' });
      } else if (fn === 'permission_required') {
        addAuthz(ctx, {
          kind: 'permission',
          name: fn,
          requirement: requirementOf(fn, argsAt(index, fn)),
          place,
          confidence: 'high',
          detail: 'Django permission_required restricts the view to users holding the named permission.',
        });
      }
    }

    for (const m of text.matchAll(/\b(LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin)\b/g)) {
      const mixin = m[1] ?? '';
      const place: Placement = { scope: 'controller', inherited: false, file: part.file, line: at(m.index ?? 0) };
      if (mixin === 'UserPassesTestMixin') {
        addAuthz(ctx, { kind: 'policy', name: mixin, requirement: null, place, confidence: 'medium', detail: 'UserPassesTestMixin applies a custom access predicate to the view class.' });
        continue;
      }
      addAuthn(ctx, { mechanism: 'framework', name: mixin, place, confidence: 'high', detail: `${mixin} requires an authenticated user for the view class.` });
      if (mixin === 'PermissionRequiredMixin') {
        addAuthz(ctx, { kind: 'permission', name: mixin, requirement: null, place, confidence: 'medium', detail: 'PermissionRequiredMixin restricts the view class to users holding the declared permission.' });
      }
    }

    for (const m of text.matchAll(/(@)?\b(permission_classes|authentication_classes)\b\s*(?:=\s*|\(\s*)[\[(]([^\])]*)[\])]/g)) {
      const list = m[2] ?? '';
      const place: Placement = { scope: m[1] === '@' ? 'decorator' : 'controller', inherited: false, file: part.file, line: at(m.index ?? 0) };
      if (list === 'permission_classes') ctx.overridesDefaultPermission = true;
      for (const token of (m[3] ?? '').split(/[,&|]/)) {
        const name = (token.trim().replace(/^~/, '').split('.').pop() ?? '').replace(/\(.*$/, '').trim();
        if (!/^[A-Za-z_]\w*$/.test(name)) continue;
        if (PUBLIC_MARKER_RE.test(name)) {
          ctx.publicMarkers.push({ name, scope: place.scope, inherited: false, file: place.file, line: place.line });
          continue;
        }
        const cls = classifyGuardName(name);
        if (list === 'authentication_classes') {
          if (cls.authn !== null) {
            addAuthn(ctx, {
              mechanism: cls.authn,
              name,
              place,
              confidence: 'low',
              detail: `${name} in authentication_classes identifies the caller but does not reject anonymous requests unless a permission class does.`,
            });
          }
          continue;
        }
        if (cls.authn !== null) {
          addAuthn(ctx, {
            mechanism: cls.authn,
            name,
            place,
            confidence: /ReadOnly/.test(name) ? 'medium' : 'high',
            detail: `Permission class ${name} ${describe(place)} requires an authenticated user${/ReadOnly/.test(name) ? ' for write methods only' : ''}.`,
          });
        }
        if (cls.authz !== null) {
          addAuthz(ctx, {
            kind: cls.authz.kind,
            name,
            requirement: cls.authz.requirement,
            place,
            confidence: cls.authz.requirement !== null ? 'high' : 'medium',
            detail: `Permission class ${name} ${describe(place)} applies a ${cls.authz.kind} restriction.`,
          });
        }
      }
    }

    for (const m of part.code.matchAll(/\bSecurity\s*\(\s*[A-Za-z_][\w.]*\s*,\s*scopes\s*=\s*\[([^\]]*)\]/g)) {
      const values = Array.from((m[1] ?? '').matchAll(/['"]([^'"]+)['"]/g)).map((x) => x[1] ?? '').filter((x) => x !== '');
      addAuthz(ctx, {
        kind: 'scope',
        name: 'Security(scopes)',
        requirement: values.length > 0 ? values.join(', ') : null,
        place: { scope: 'dependency', inherited: false, file: part.file, line: lineAtOffset(part.code, m.index ?? 0, part.startLine) },
        confidence: 'high',
        detail: 'FastAPI Security dependency declares required OAuth scopes.',
      });
    }
  }
}

function propKind(prop: string): AuthorizationKind {
  if (/^permissions?$/i.test(prop)) return 'permission';
  if (/^scopes?$/i.test(prop)) return 'scope';
  if (/admin|staff|superuser/i.test(prop)) return 'admin_flag';
  return 'role';
}

function callKind(name: string): AuthorizationKind {
  if (/role/i.test(name)) return 'role';
  if (/perm|^can|access|allowed/i.test(name)) return 'permission';
  return 'policy';
}

function decisionOnVariable(lines: readonly string[], variable: string, skip: number): boolean {
  const v = escapeRegExp(variable);
  const re = new RegExp(
    `!\\s*${v}(?![\\w$])|(?<![\\w$.])${v}\\s*(?:===|==|!==|!=)\\s*(?:null|undefined|None)\\b|\\bif\\s*\\(\\s*${v}\\s*\\)|\\bnot\\s+${v}\\b|\\b${v}\\s+is\\s+(?:not\\s+)?None\\b|\\bif\\s+${v}\\s*:`
  );
  return lines.some((l, i) => i !== skip && re.test(l));
}

function inlineControls(ctx: Ctx): void {
  const idNames = Array.from(new Set(ctx.identities.map((i) => i.name))).sort((a, b) => b.length - a.length);
  const idAlt = idNames.map(escapeRegExp).join('|');
  const negJs =
    idAlt === ''
      ? null
      : new RegExp(
          `!\\s*(?:${idAlt})(?![\\w$.])|(?<![\\w$.])(?:${idAlt})\\s*(?:===|==)\\s*(?:null|undefined)(?![\\w$])|!\\s*(?:${idAlt})\\s*\\.\\s*(?:id|_id|sub|uid|userId|email)(?![\\w$])`
        );
  const negPy =
    idAlt === ''
      ? null
      : new RegExp(
          `\\bnot\\s+(?:${idAlt})(?![\\w$.])|(?<![\\w$.])(?:${idAlt})\\s+is\\s+None\\b|\\bnot\\s+(?:${idAlt})\\s*\\.\\s*is_authenticated\\b|(?<![\\w$.])(?:${idAlt})\\s*\\.\\s*is_anonymous\\b`
        );
  const propRe =
    idAlt === '' ? null : new RegExp(`(?<![\\w$.])(?:${idAlt})(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*?\\s*\\.\\s*(${PROP_SRC})(?![\\w$])`, 'g');
  const callRe = new RegExp(`((?:[A-Za-z_$][\\w$]*\\s*\\.\\s*)*)\\b(${CALL_NAMES})\\s*\\(([^\\n]{0,200})`, 'g');
  const idArgRe = idAlt === '' ? null : new RegExp(`(?<![\\w$.])(?:${idAlt})(?![\\w$])`);

  for (const part of ctx.source.parts) {
    const python = part.file.endsWith('.py');
    const lines = part.plain.split('\n');
    const rawLines = part.code.split('\n');
    const partHasVerify = lines.some((l) => VERIFY_RE.test(l));
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.trim() === '') continue;
      const raw = rawLines[i] ?? '';
      const here: Placement = { scope: 'handler', inherited: false, file: part.file, line: part.startLine + i };
      const rejects = REJECT_RE.test(lines.slice(i, i + 4).join(' '));

      for (const rule of CALL_RULES) {
        const hit = rule.re.exec(line);
        if (!hit) continue;
        let confidence: Confidence = 'high';
        let detail = `Handler performs a ${rule.label}.`;
        if (rule.lookup) {
          if (python && rule.label === 'jwt.decode call') {
            if (/verify_signature['"]?\s*[:=]\s*False|verify\s*=\s*False/.test(rawLines.slice(i, i + 3).join(' '))) continue;
          } else {
            const assign = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=/.exec(line) ?? /^\s*([A-Za-z_]\w*)\s*=(?!=)/.exec(line);
            const variable = assign?.[1];
            const decided = variable !== undefined && decisionOnVariable(lines, variable, i);
            confidence = decided || rejects ? 'high' : 'low';
            detail = `Handler performs a ${rule.label}${confidence === 'high' ? ' and rejects the request when it fails' : ' but no visible rejection of unauthenticated callers follows'}.`;
          }
        }
        addAuthn(ctx, { mechanism: rule.mechanism, name: hit[0].replace(/\s+/g, ' ').trim(), place: here, confidence, detail });
      }

      if (BEARER_HEADER_RE.test(raw) || (python && PY_HEADER_PARAM_RE.test(line))) {
        addAuthn(ctx, {
          mechanism: 'bearer',
          name: 'Authorization header',
          place: here,
          confidence: partHasVerify ? 'high' : 'medium',
          detail: `Handler reads the Authorization header${partHasVerify ? ' and verifies a token' : ' without a visible verification call in the same handler'}.`,
        });
      }
      if (API_KEY_HEADER_RE.test(raw)) {
        addAuthn(ctx, { mechanism: 'api_key', name: 'X-API-Key header', place: here, confidence: 'medium', detail: 'Handler reads an API key header.' });
      }

      const sess = /\b(?:req|request)\s*\.\s*(session|cookies|signedCookies|COOKIES)\b/.exec(line);
      if (sess && rejects && (DECISION_RE.test(line) || line.includes('!'))) {
        const cookie = /cookies|COOKIES|signedCookies/.test(sess[1] ?? '');
        addAuthn(ctx, {
          mechanism: cookie ? 'cookie' : 'session',
          name: sess[0].replace(/\s+/g, ''),
          place: here,
          confidence: 'medium',
          detail: `Handler rejects requests based on ${cookie ? 'cookie' : 'session'} state.`,
        });
      }

      const neg = python ? negPy : negJs;
      if (neg && rejects) {
        const hit = neg.exec(line);
        if (hit) {
          addAuthn(ctx, {
            mechanism: 'generic',
            name: hit[0].replace(/\s+/g, ' ').trim(),
            place: here,
            confidence: 'high',
            detail: 'Handler rejects the request when the authenticated identity is missing.',
          });
        }
      }

      if (propRe && (DECISION_RE.test(line) || DECISION_RE.test(lines[i - 1] ?? ''))) {
        for (const m of line.matchAll(propRe)) {
          const prop = m[1] ?? '';
          const kind = propKind(prop);
          const requirement = /['"]([^'"\s]{1,40})['"]/.exec(raw)?.[1] ?? null;
          addAuthz(ctx, {
            kind,
            name: m[0].replace(/\s+/g, ''),
            requirement,
            place: here,
            confidence: rejects ? 'high' : 'medium',
            detail: `Handler compares the authenticated identity's ${prop} in a decision${rejects ? ' followed by a rejection' : ''}.`,
          });
        }
      }

      for (const m of line.matchAll(callRe)) {
        const prefix = (m[1] ?? '').replace(/\s+/g, '').replace(/\.$/, '');
        const callee = m[2] ?? '';
        const args = m[3] ?? '';
        const onIdentity = prefix !== '' && idNames.some((n) => prefix === n || prefix.startsWith(`${n}.`));
        const withIdentity = idArgRe !== null && idArgRe.test(args);
        if (!onIdentity && !withIdentity) continue;
        addAuthz(ctx, {
          kind: callKind(callee),
          name: prefix === '' ? callee : `${prefix}.${callee}`,
          requirement: /['"]([^'"\s]{1,40})['"]/.exec(raw)?.[1] ?? null,
          place: here,
          confidence: rejects || DECISION_RE.test(line) ? 'high' : 'medium',
          detail: `Handler calls ${callee}() with the authenticated identity.`,
        });
      }
    }
  }
}

function globalControls(ctx: Ctx): void {
  const { entry, shared } = ctx;
  const named = new Set([...entry.middleware, ...entry.dependencies].map((n) => splitCall(n).base));
  const drf = ctx.source.parts.some((p) => DRF_RE.test(p.plain));
  for (const g of shared.globals) {
    if (g.framework !== entry.framework || !g.matches(entry.path)) continue;
    if (g.kind === 'middleware' || g.kind === 'dependency' || named.has(g.base)) continue;
    const place: Placement = { scope: 'global', inherited: true, file: g.file, line: g.line };
    if (g.kind === 'edge_middleware') {
      addAuthn(ctx, {
        mechanism: g.mechanism ?? 'session',
        name: 'middleware',
        place,
        confidence: 'medium',
        detail: 'Next.js middleware with authentication logic applies to this route through its matcher.',
      });
      continue;
    }
    if ((g.kind === 'default_permission' || g.kind === 'default_authentication') && !drf) continue;
    if (g.kind === 'default_permission' && ctx.overridesDefaultPermission) continue;
    if (PUBLIC_MARKER_RE.test(g.base)) {
      ctx.publicMarkers.push({ name: g.base, scope: 'global', inherited: true, file: g.file, line: g.line });
      continue;
    }
    const cls = classifyGuardName(g.base);
    const assessment = g.kind === 'guard' ? assessGuard(shared, g.base, g.file) : null;
    if (cls.authn !== null) {
      const identifyOnly = g.kind === 'default_authentication';
      addAuthn(ctx, {
        mechanism: cls.authn,
        name: g.name,
        place,
        confidence: identifyOnly ? 'low' : assessment ? guardConfidence(cls.authn === 'generic' ? 'medium' : 'high', assessment) : 'high',
        assessment,
        detail: identifyOnly
          ? `Global default authentication class ${g.base} identifies the caller but does not reject anonymous requests on its own.`
          : `Global ${g.kind === 'guard' ? 'guard' : 'default permission class'} ${g.base} applies to every route in the application.`,
      });
    }
    if (cls.authz !== null && g.kind !== 'default_authentication') {
      addAuthz(ctx, {
        kind: cls.authz.kind,
        name: g.name,
        requirement: cls.authz.requirement,
        place,
        confidence: assessment ? guardConfidence(cls.authz.requirement !== null ? 'high' : 'medium', assessment) : cls.authz.requirement !== null ? 'high' : 'medium',
        assessment,
        detail: `Global ${g.kind === 'guard' ? 'guard' : 'default permission class'} ${g.base} applies a ${cls.authz.kind} restriction to every route.`,
      });
    }
  }
}

export function createControlShared(resolver: SourceResolver, globals: readonly GlobalGuard[]): ControlShared {
  return { resolver, globals, locations: new Map(), assessments: new Map() };
}

export function collectEntryControls(
  entry: AttackSurfaceEntry,
  source: RouteSource,
  identities: readonly IdentitySource[],
  shared: ControlShared
): EntryControls {
  const ctx: Ctx = {
    entry,
    source,
    shared,
    identities,
    authn: new Map(),
    authz: new Map(),
    publicMarkers: [],
    overridesDefaultPermission: false,
  };
  namedControls(ctx);
  if (entry.framework === 'nestjs') decoratorControls(ctx);
  pythonControls(ctx);
  inlineControls(ctx);
  globalControls(ctx);
  return {
    authentication: Array.from(ctx.authn.values()),
    authorization: Array.from(ctx.authz.values()),
    publicMarkers: ctx.publicMarkers,
  };
}
