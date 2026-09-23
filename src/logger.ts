/**
 * Minimal structured logger.
 *
 * All MCP servers talking over stdio MUST NOT write logs to stdout, since
 * stdout is the JSON-RPC transport channel. Everything goes to stderr.
 *
 * Logger also redacts values that look like secrets (API keys, tokens,
 * passwords, bearer headers) before they are ever serialized.
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const SECRET_KEY_PATTERN =
  /(api[_-]?key|token|secret|password|authorization|bearer|access[_-]?key)/i;

const SECRET_VALUE_PATTERN =
  /\b(sk-[a-zA-Z0-9_-]{10,}|ghp_[a-zA-Z0-9]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g;

function redactValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return value.replace(SECRET_VALUE_PATTERN, '[REDACTED]');
  }
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }
  if (value && typeof value === 'object') {
    return redactObject(value as Record<string, unknown>);
  }
  return value;
}

function redactObject(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (SECRET_KEY_PATTERN.test(key)) {
      out[key] = '[REDACTED]';
    } else {
      out[key] = redactValue(val);
    }
  }
  return out;
}

function write(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...(meta ? { meta: redactObject(meta) } : {}),
  };
  // Always stderr — never stdout (reserved for MCP JSON-RPC transport).
  process.stderr.write(JSON.stringify(entry) + '\n');
}

export const logger = {
  debug: (message: string, meta?: Record<string, unknown>) => write('debug', message, meta),
  info: (message: string, meta?: Record<string, unknown>) => write('info', message, meta),
  warn: (message: string, meta?: Record<string, unknown>) => write('warn', message, meta),
  error: (message: string, meta?: Record<string, unknown>) => write('error', message, meta),
};

export { redactObject, redactValue };
