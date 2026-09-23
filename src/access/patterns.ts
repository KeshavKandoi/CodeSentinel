import type { AuthMechanism, AuthorizationKind } from './types.js';

export interface GuardClass {
  base: string;
  args: string | null;
  authn: AuthMechanism | null;
  authz: { kind: AuthorizationKind; requirement: string | null } | null;
}

const NON_ACCESS_RE =
  /rate[-_]?limit|throttl|cors|helmet|morgan|logger|logging|compress|body[-_]?parser|cookie[-_]?parser|csrf|xsrf|multer|upload|multipart|swagger|healthcheck|express\.(?:json|urlencoded|static|text|raw)|^(?:express[-_.]?)?(?:cookie)?session$|(?:router|routes|controller|module|plugin|service|schema|dto)$/i;

const AUTHN_RULES: Array<[RegExp, AuthMechanism]> = [
  [/jwt|jsonwebtoken|jwks/i, 'jwt'],
  [/oidc|openid/i, 'oidc'],
  [/oauth|auth0|okta|keycloak|clerk|next-?auth|nextauth|cognito|supabase/i, 'oauth'],
  [/bearer/i, 'bearer'],
  [/api[-_]?key|apikey/i, 'api_key'],
  [/basic[-_]?auth|httpbasic/i, 'basic'],
  [/passport/i, 'passport'],
  [/(?:require|check|verify|valid(?:ate)?|ensure|has|active)[-_]?session|session[-_]?(?:required|guard|check|verify|valid|auth)/i, 'session'],
  [/cookie[-_]?(?:auth|required|guard|check|verify)|(?:verify|check|require)[-_]?cookie/i, 'cookie'],
  [/login[-_]?required|loginrequired|logged[-_]?in|ensure[-_]?login|is[-_]?authenticated|isauthenticated|staff[-_]?member[-_]?required/i, 'framework'],
  [/verify.*token|validate.*token|check.*token|token.*(?:guard|required|middleware|verify|check)/i, 'bearer'],
  [/authguard/i, 'guard'],
  [
    /(?:^|[^A-Za-z])(?:auth|Auth|AUTH)(?![a-z])|[a-z]Auth(?![a-z])|[Aa]uthenticat|AUTHENTICAT|current[_-]?(?:active[_-]?)?[Uu]ser|CurrentUser|get[_-]?current|[Rr]equire[_-]?[Uu]ser|[Rr]equire[_-]?[Ll]ogin|withAuth|[Pp]rotect(?:ed)?$/,
    'generic',
  ],
];

const AUTHZ_RULES: Array<[RegExp, AuthorizationKind]> = [
  [/owner|ownership|belongs[-_]?to|is[-_]?self|same[-_]?user/i, 'ownership'],
  [/tenant|organi[sz]ation[-_]?(?:guard|member|access|check|required)|workspace[-_]?(?:guard|member|access|check)/i, 'tenant'],
  [/scope/i, 'scope'],
  [/permission|has[-_]?perms?|require[-_]?perms?|abilit|casl|entitle|rbac/i, 'permission'],
  [/role|admin|staff|superuser/i, 'role'],
  [/polic(?:y|ies)|authoriz|user[-_]?passes[-_]?test|enforce|guardian/i, 'policy'],
];

const CAN_RE = /^(?:can|cannot)(?:[A-Z_]|$)/;

export const PUBLIC_MARKER_RE = /^(?:Public|IsPublic|SkipAuth|SkipJwtAuth|AllowAnonymous|AllowAny|NoAuth|Anonymous|AuthOptional|Unprotected|permitAll)$/i;

export const DECISION_RE =
  /\bif\b|\belif\b|\bunless\b|\bwhile\b|\bassert\b|\braise\b|\bthrow\b|===|!==|==|!=|\.includes\s*\(|\.some\s*\(|\.has\s*\(|&&|\|\||\bnot\b|\bin\s*\[/;

export const REJECT_RE =
  /\b40[13]\b|unauthori[sz]ed|forbidden|HTTPException|PermissionDenied|PermissionError|\babort\s*\(|\.status\s*\(\s*40[13]|\.code\s*\(\s*40[13]|status_code\s*=\s*40[13]|\bredirect\s*\(|NotAuthorized|\bthrow\b|\braise\b/i;

export const ENFORCEMENT_RE =
  /jwt\.verify|jwtVerify|verifyToken|\.verify\s*\(|\.decode\s*\(|passport|AuthGuard\s*\(|canActivate|\breq\.user\s*=|\brequest\.user\s*=|isAuthenticated|getServerSession|\bhas_perm|is_staff|is_superuser|\bHTTPException|\braise\b|\bthrow\b|\b40[13]\b|Unauthorized|Forbidden|PermissionDenied|\babort\s*\(/;

export function splitCall(raw: string): { base: string; args: string | null } {
  const trimmed = raw.trim();
  const m = /^([A-Za-z_$@][\w$.]*)\s*(?:\(([\s\S]*)\))?\s*$/.exec(trimmed);
  if (!m) return { base: trimmed, args: null };
  return { base: m[1] ?? trimmed, args: m[2] ?? null };
}

export function requirementOf(base: string, args: string | null): string | null {
  const values: string[] = [];
  if (args) {
    const re = /['"]([^'"]{1,64})['"]|\b(?:Role|Roles|Permission|Permissions|UserRole|Scope|Scopes)\s*\.\s*([A-Za-z_]\w*)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(args)) !== null) {
      const value = m[1] ?? m[2] ?? '';
      if (value !== '') values.push(value);
    }
  }
  if (values.length === 0 && /admin/i.test(base)) values.push('admin');
  if (values.length === 0 && /staff/i.test(base)) values.push('staff');
  if (values.length === 0 && /superuser/i.test(base)) values.push('superuser');
  return values.length > 0 ? Array.from(new Set(values)).join(', ') : null;
}

function refineMechanism(mechanism: AuthMechanism, args: string | null): AuthMechanism {
  if (!args) return mechanism;
  if (/jwt/i.test(args)) return 'jwt';
  if (/google|github|facebook|twitter|oauth|azure|okta|discord|apple|microsoft|saml|oidc/i.test(args)) return 'oauth';
  return mechanism;
}

export function classifyGuardName(raw: string): GuardClass {
  const { base, args } = splitCall(raw);
  const empty: GuardClass = { base, args, authn: null, authz: null };
  if (base === '' || NON_ACCESS_RE.test(base)) return empty;

  let authn: AuthMechanism | null = null;
  for (const [re, mechanism] of AUTHN_RULES) {
    if (re.test(base)) {
      authn = mechanism;
      break;
    }
  }
  if (authn === 'passport' || authn === 'guard') authn = refineMechanism(authn, args);

  let authz: GuardClass['authz'] = null;
  const last = base.split('.').pop() ?? base;
  if (CAN_RE.test(last)) {
    authz = { kind: 'permission', requirement: requirementOf(base, args) };
  } else {
    for (const [re, kind] of AUTHZ_RULES) {
      if (re.test(base)) {
        authz = { kind, requirement: requirementOf(base, args) };
        break;
      }
    }
  }
  return { base, args, authn, authz };
}
