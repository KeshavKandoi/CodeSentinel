import type { HttpMethod } from '../routes/types.js';
import { validateRedirect, validateUrl } from './targetGuard.js';
import type { RuntimeResponse, RuntimeTarget, TestSession, VerificationEvidence } from './types.js';
import type { RuntimeRequest } from './types.js';

/**
 * Hardened HTTP client for controlled runtime verification. Every request
 * passes through targetGuard's validateUrl/validateRedirect before being
 * sent. Never sends headers/cookies/credentials other than what the caller
 * explicitly attached to a TestSession or a single RuntimeRequest -- nothing
 * is read automatically from project files or the process environment here.
 * Sensitive header values and known secret-shaped body content are redacted
 * before being retained as evidence.
 */

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 200_000;
const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_MIN_INTERVAL_MS = 50;
const DEFAULT_MAX_CONCURRENCY = 2;
const DEFAULT_MAX_REQUESTS_PER_CASE = 12;

const ALLOWED_METHODS = new Set<HttpMethod>(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const UNSAFE_METHODS = new Set<HttpMethod>(['POST', 'PUT', 'PATCH', 'DELETE']);

const SENSITIVE_HEADER_RE = /^(authorization|cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|x-access-token)$/i;
const SENSITIVE_VALUE_RE =
  /\b(sk-[a-zA-Z0-9_-]{10,}|ghp_[a-zA-Z0-9]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{10,})\b/g;
const SENSITIVE_BODY_FIELD_RE = /("?(?:authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret)"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^,;\s}]+)/gi;

function redactHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') {
      const attributes = value.split(';').slice(1).map((part) => part.trim().split('=')[0].toLowerCase()).filter(Boolean);
      out[key] = `cookie-attributes:${[...new Set(attributes)].sort().join(',')}`;
    } else {
      out[key] = SENSITIVE_HEADER_RE.test(key) ? '[REDACTED]' : value.replace(SENSITIVE_VALUE_RE, '[REDACTED]');
    }
  });
  return out;
}

function redactBody(text: string): string {
  return text.replace(SENSITIVE_VALUE_RE, '[REDACTED]').replace(SENSITIVE_BODY_FIELD_RE, '$1[REDACTED]');
}

function toEvidence(req: RuntimeRequest, response: RuntimeResponse, note: string): VerificationEvidence {
  return { request: { method: req.method, path: req.path, sessionId: req.sessionId }, response, note };
}

function blockedEvidence(req: RuntimeRequest, reason: string): VerificationEvidence {
  return toEvidence(
    req,
    { status: 0, headers: {}, bodySnippet: '', bodyTruncated: false, durationMs: 0, redirected: false, finalUrl: '' },
    `Blocked: ${reason}`
  );
}

/** Tracks per-verification-case request count, a simple min-interval rate
 * limit, and a bounded-concurrency semaphore. One instance per case run --
 * never shared across cases, so limits are always scoped to a single
 * hypothesis rather than the whole server lifetime. */
export class RuntimeClientState {
  requestsIssued = 0;
  private lastRequestAt = 0;
  private active = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly target: RuntimeTarget) {}

  private get maxConcurrency(): number {
    return this.target.maxConcurrency ?? DEFAULT_MAX_CONCURRENCY;
  }
  private get minInterval(): number {
    return this.target.minRequestIntervalMs ?? DEFAULT_MIN_INTERVAL_MS;
  }
  private get maxRequests(): number {
    return this.target.maxRequestsPerCase ?? DEFAULT_MAX_REQUESTS_PER_CASE;
  }

  canIssue(): boolean {
    return this.requestsIssued < this.maxRequests;
  }

  private async acquire(): Promise<void> {
    if (this.active < this.maxConcurrency) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
    this.active++;
  }

  private release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) next();
  }

  private async throttle(): Promise<void> {
    const now = Date.now();
    const wait = this.lastRequestAt + this.minInterval - now;
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    this.lastRequestAt = Date.now();
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      await this.throttle();
      if (this.requestsIssued >= this.maxRequests) {
        throw new Error('RUNTIME_REQUEST_LIMIT');
      }
      this.requestsIssued++;
      return await fn();
    } finally {
      this.release();
    }
  }
}

async function readBodyCapped(response: Response, maxBytes: number): Promise<{ text: string; truncated: boolean }> {
  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text().catch(() => '');
    return { text: text.slice(0, maxBytes), truncated: text.length > maxBytes };
  }
  const decoder = new TextDecoder();
  let received = 0;
  let out = '';
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      received += value.byteLength;
      if (received > maxBytes) {
        const remaining = Math.max(0, maxBytes - (received - value.byteLength));
        out += decoder.decode(value.subarray(0, remaining), { stream: false });
        truncated = true;
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
        break;
      }
      out += decoder.decode(value, { stream: true });
    }
  }
  return { text: out, truncated };
}

async function performRequest(
  target: RuntimeTarget,
  url: URL,
  req: RuntimeRequest,
  session: TestSession | null,
  state: RuntimeClientState
): Promise<VerificationEvidence> {
  const timeoutMs = target.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = target.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const maxRedirects = target.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  let currentUrl = url;
  let hop = 0;
  const startedAt = Date.now();
  const headers: Record<string, string> = { ...(session?.headers ?? {}), ...(req.headers ?? {}) };

  for (;;) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await state.run(() => fetch(currentUrl, {
          method: req.method,
          headers,
          body: req.body,
          redirect: 'manual',
          signal: controller.signal,
        }));
    } catch (e) {
      clearTimeout(timer);
      if ((e as Error).message === 'RUNTIME_REQUEST_LIMIT') {
        return blockedEvidence(req, 'Per-case request limit reached while following redirects; no further requests issued.');
      }
      return toEvidence(
        req,
        {
          status: 0,
          headers: {},
          bodySnippet: '',
          bodyTruncated: false,
          durationMs: Date.now() - startedAt,
          redirected: hop > 0,
          finalUrl: currentUrl.toString(),
        },
        'Request failed or timed out before a response was received.'
      );
    }
    clearTimeout(timer);

    if (response.status >= 300 && response.status < 400 && response.headers.has('location')) {
      hop++;
      if (hop > maxRedirects) {
        return toEvidence(
          req,
          {
            status: response.status,
            headers: redactHeaders(response.headers),
            bodySnippet: '',
            bodyTruncated: false,
            durationMs: Date.now() - startedAt,
            redirected: true,
            finalUrl: currentUrl.toString(),
          },
          `Redirect limit (${maxRedirects}) exceeded; not followed further.`
        );
      }
      const location = response.headers.get('location')!;
      const redirectCheck = await validateRedirect(target, location, currentUrl);
      if (!redirectCheck.ok) {
        return toEvidence(
          req,
          {
            status: response.status,
            headers: redactHeaders(response.headers),
            bodySnippet: '',
            bodyTruncated: false,
            durationMs: Date.now() - startedAt,
            redirected: true,
            finalUrl: currentUrl.toString(),
          },
          `Redirect blocked: ${redirectCheck.reason}`
        );
      }
      currentUrl = redirectCheck.url;
      continue;
    }

    const { text, truncated } = await readBodyCapped(response, maxBytes);
    return toEvidence(
      req,
      {
        status: response.status,
        headers: redactHeaders(response.headers),
        bodySnippet: redactBody(text),
        bodyTruncated: truncated,
        durationMs: Date.now() - startedAt,
        redirected: hop > 0,
        finalUrl: currentUrl.toString(),
      },
      'Response received.'
    );
  }
}

/** The single entrypoint every verification case must use to issue a
 * request. Validates method allowlist, per-case request cap, and target
 * boundary (via targetGuard) before anything is sent, then runs the
 * request through the rate-limit/concurrency-bounded state. */
export async function issueRuntimeRequest(
  target: RuntimeTarget,
  sessions: Map<string, TestSession>,
  req: RuntimeRequest,
  state: RuntimeClientState
): Promise<VerificationEvidence> {
  if (!ALLOWED_METHODS.has(req.method as HttpMethod)) {
    return blockedEvidence(req, `Method "${req.method}" is not permitted for runtime verification.`);
  }
  if (UNSAFE_METHODS.has(req.method) && (target.allowDestructiveMethods !== true || !target.vettedTestPaths?.includes(req.path))) {
    return blockedEvidence(req, `Method "${req.method}" is blocked unless allowDestructiveMethods is true and the exact path is listed in vettedTestPaths.`);
  }
  if (!state.canIssue()) return blockedEvidence(req, 'Per-case request limit reached; no further requests issued.');

  const validated = await validateUrl(target, req.path);
  if (!validated.ok) return blockedEvidence(req, validated.reason);

  const session = req.sessionId ? sessions.get(req.sessionId) ?? null : null;
  if (req.sessionId && !session) {
    return blockedEvidence(req, `Requested session "${req.sessionId}" is not configured.`);
  }

  try {
    return await performRequest(target, validated.url, req, session, state);
  } catch (e) {
    if ((e as Error).message === 'RUNTIME_REQUEST_LIMIT') {
      return blockedEvidence(req, 'Per-case request limit reached; no further requests issued.');
    }
    return blockedEvidence(req, 'Runtime request was blocked before it was sent.');
  }
}
