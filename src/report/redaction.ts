const SECRET_KEY_RE = /authorization|cookie|set-cookie|api[_-]?key|bearer|token|password|secret|credential|environment|env/i;
const SECRET_VALUE_RE = /Bearer\s+[A-Za-z0-9._-]+|\b(?:sk|ghp|xox[baprs])[-_][A-Za-z0-9._-]+|AKIA[0-9A-Z]{16}/gi;

const JWT_RE = /\beyJ[\w-]{5,}\.[\w-]{5,}\.(?!invalid-signature\b)[\w-]{5,}/g;
const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const URL_CRED_RE = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s\/:@]+:[^\s\/@]+@/gi;
const SECRET_PAIR_RE = /("?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&\s,;}]+)/gi;

const AUTH_SCHEME_RE = /\b(Authorization\s*:\s*)(?:Basic|Digest|Token)\s+[^\s,;"]+/gi;
const BASIC_B64_RE = /\bBasic\s+[A-Za-z0-9+\/]{8,}={1,2}/g;
const COOKIE_HEADER_RE = /\b((?:Set-)?Cookie\s*:\s*)[A-Za-z0-9_.-]+=[^\r\n]*/gi;

function redactString(text: string): string {
  return text
    .replace(PEM_RE, '[REDACTED]')
    .replace(JWT_RE, '[REDACTED]')
    .replace(URL_CRED_RE, '$1[REDACTED]@')
    .replace(SECRET_PAIR_RE, '$1[REDACTED]')
    .replace(AUTH_SCHEME_RE, '$1[REDACTED]')
    .replace(BASIC_B64_RE, '[REDACTED]')
    .replace(COOKIE_HEADER_RE, '$1[REDACTED]')
    .replace(SECRET_VALUE_RE, '[REDACTED]');
}

export function redactReportValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[TRUNCATED]';
  if (typeof value === 'string') return redactString(value).slice(0, 2_000);
  // Keep report arrays bounded, but preserve the evidence graph's references.
  // Deep audits cap evidence at 1,000 items; truncating this to 100 after
  // integrity validation would silently return findings pointing at absent
  // evidence IDs.
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
