const SECRET_KEY_RE = /authorization|cookie|set-cookie|api[_-]?key|bearer|token|password|secret|credential|environment|env/i;
const SECRET_VALUE_RE = /Bearer\s+[A-Za-z0-9._~+\/=-]+|\b(?:sk|gh[pousr]|github_pat|xox[baprs])[-_][A-Za-z0-9._-]+|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}/gi;

const JWT_RE = /\beyJ[\w-]{5,}\.[\w-]{5,}\.(?!invalid-signature\b)[\w-]{5,}/g;
const UNSIGNED_JWT_RE = /\beyJ[\w-]{5,}\.[\w-]{5,}\.(?![\w-])/g;
const URL_TOKEN_RE = /\b([a-z][a-z0-9+.-]*:\/\/)[A-Za-z0-9_-]{16,}@/gi;
const AUTHZ_RAW_RE = /\b((?:Proxy-)?Authorization\s*:\s*)[^\s,;"]{8,}/gi;
const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const URL_CRED_RE = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s\/:@]+:[^\s\/@]+@/gi;
const SECRET_PAIR_RE = /("?\b[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|private[_-]?key)[A-Za-z0-9_-]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&\s,;}]+)/gi;

const DIGEST_RE = /\b((?:Proxy-)?Authorization\s*:\s*Digest\s+)[^\r\n]*/gi;
const AUTH_SCHEME_RE = /\b(Authorization\s*:\s*)(?:Basic|Digest|Token)\s+[^\s,;"]+/gi;
const BASIC_B64_RE = /\bBasic\s+(?=[A-Za-z0-9+\/]+[A-Z0-9+\/])[A-Za-z0-9+\/]{8,}={0,2}/g;
const TOKEN_JSON_RE = /("[A-Za-z0-9_.-]*token[A-Za-z0-9_-]*"\s*:\s*)("[^"]*"|'[^']*')/gi;
const COOKIE_HEADER_RE = /\b((?:Set-)?Cookie\s*:\s*)[A-Za-z0-9_.-]+=[^\r\n]*/gi;

function redactString(text: string): string {
  return text
    .replace(PEM_RE, '[REDACTED]')
    .replace(JWT_RE, '[REDACTED]')
    .replace(UNSIGNED_JWT_RE, '[REDACTED]')
    .replace(URL_CRED_RE, '$1[REDACTED]@')
    .replace(URL_TOKEN_RE, '$1[REDACTED]@')
    .replace(SECRET_PAIR_RE, '$1[REDACTED]')
    .replace(TOKEN_JSON_RE, '$1"[REDACTED]"')
    .replace(DIGEST_RE, '$1[REDACTED]')
    .replace(AUTH_SCHEME_RE, '$1[REDACTED]')
    .replace(AUTHZ_RAW_RE, '$1[REDACTED]')
    .replace(BASIC_B64_RE, '[REDACTED]')
    .replace(COOKIE_HEADER_RE, '$1[REDACTED]')
    .replace(SECRET_VALUE_RE, '[REDACTED]');
}

export function redactReportValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[TRUNCATED]';
  if (typeof value === 'string') return redactString(value).slice(0, 2_000);
  if (Array.isArray(value)) return value.slice(0, 1_000).map((item) => redactReportValue(item, depth + 1));
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) output[key] = SECRET_KEY_RE.test(key) ? '[REDACTED]' : redactReportValue(child, depth + 1);
    return output;
  }
  return value;
}

export function detachedRedacted<T>(value: T): T {
  return JSON.parse(JSON.stringify(redactReportValue(value))) as T;
}
