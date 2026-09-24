const SECRET_KEY_RE = /authorization|cookie|set-cookie|api[_-]?key|bearer|token|password|secret|credential|environment|env/i;
const SECRET_VALUE_RE = /Bearer\s+[A-Za-z0-9._-]+|(?:sk|ghp|xox[baprs])[-_][A-Za-z0-9._-]+|AKIA[0-9A-Z]{16}/gi;

export function redactReportValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[TRUNCATED]';
  if (typeof value === 'string') return value.replace(SECRET_VALUE_RE, '[REDACTED]').slice(0, 2_000);
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => redactReportValue(item, depth + 1));
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
