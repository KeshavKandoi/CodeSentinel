/**
 * Name/pattern based classification of guards (middleware, dependencies,
 * decorators). These are static heuristics: they produce *indicators*, never
 * proof that a route is or is not protected.
 */
const NON_AUTH_RE = /rate[-_]?limit|throttl|cors|helmet|morgan|logger|compression|bodyparser|express\.(json|urlencoded|static)/i;
const AUTHN_RE = /(authenticat|auth(?!oriz)|jwt|passport|session|bearer|token|login|signin|protect|requireuser|isloggedin|api[_-]?key|basicauth)/i;
const AUTHZ_RE = /(authoriz|role|permission|admin|\bacl\b|rbac|policy|casl|scope|isowner|ownership|checkaccess|hasaccess|\bcan\()/i;

export function classifyGuard(name: string): { authentication: boolean; authorization: boolean } {
  if (NON_AUTH_RE.test(name)) return { authentication: false, authorization: false };
  return { authentication: AUTHN_RE.test(name), authorization: AUTHZ_RE.test(name) };
}

export function classifyGuards(names: readonly string[]): { authentication: string[]; authorization: string[] } {
  const authentication: string[] = [];
  const authorization: string[] = [];
  for (const name of names) {
    const c = classifyGuard(name);
    if (c.authentication) authentication.push(name);
    if (c.authorization) authorization.push(name);
  }
  return { authentication, authorization };
}

const INLINE_AUTHN: Array<[RegExp, string]> = [
  [/\breq\.user\b/, 'inline: req.user check'],
  [/\breq\.session\b/, 'inline: req.session check'],
  [/\bisAuthenticated\s*\(/, 'inline: isAuthenticated()'],
  [/\bgetServerSession\s*\(|\bgetSession\s*\(|\bgetToken\s*\(/, 'inline: session/token lookup'],
  [/\bauth\s*\(\s*\)/, 'inline: auth() call'],
  [/\bjwt\s*\.\s*verify\s*\(/, 'inline: jwt.verify'],
  [/headers\s*\.\s*authorization|headers\s*\[\s*['"]authorization['"]\s*\]|\.header\s*\(\s*['"]authorization['"]\s*\)/i, 'inline: Authorization header check'],
];
const INLINE_AUTHZ: Array<[RegExp, string]> = [
  [/\.roles?\b/, 'inline: role check'],
  [/\bisAdmin\b/, 'inline: isAdmin check'],
  [/\bhasPermission\s*\(|\bcheckPermission\s*\(|\bcan\s*\(/, 'inline: permission check'],
];

export function inlineAuthIndicators(code: string): { authn: string[]; authz: string[] } {
  const authn = INLINE_AUTHN.filter(([re]) => re.test(code)).map(([, label]) => label);
  const authz = INLINE_AUTHZ.filter(([re]) => re.test(code)).map(([, label]) => label);
  return { authn, authz };
}

const UPLOAD_NAME_RE = /(multer|upload|formidable|busboy|multipart|fileupload)/i;

export function detectUploadIndicators(names: readonly string[], code: string): string[] {
  const out: string[] = [];
  for (const name of names) {
    if (UPLOAD_NAME_RE.test(name)) out.push(`middleware: ${name}`);
  }
  if (/\breq\s*\.\s*files?\b/.test(code)) out.push('code: req.file/req.files');
  if (/multipart\/form-data/i.test(code)) out.push('code: multipart/form-data');
  if (/\.formData\s*\(\s*\)/.test(code)) out.push('code: request.formData()');
  return out;
}
