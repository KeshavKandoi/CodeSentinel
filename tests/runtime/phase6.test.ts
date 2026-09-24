import { afterEach, describe, expect, it, vi } from 'vitest';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyFinding, listVerificationCases } from '../../src/runtime/engine.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { issueRuntimeRequest, RuntimeClientState } from '../../src/runtime/httpClient.js';
import { validateRedirect, validateTarget, validateUrl } from '../../src/runtime/targetGuard.js';
import type { AppConfig } from '../../src/config.js';
import type { RuntimeTarget } from '../../src/runtime/types.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const RUNTIME_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/runtime-phase6', import.meta.url)));
const config: AppConfig = {
  projectRoot: FIXTURE,
  commandTimeoutMs: 5000,
  maxOutputBytes: 1_000_000,
  maxReadFileBytes: 2_000_000,
  maxListResults: 2_000,
};
const target: RuntimeTarget = { allowedOrigin: 'http://127.0.0.1:43127', minRequestIntervalMs: 0 };

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Phase 6 target boundary', () => {
  it('rejects malformed origins, credentials, paths, and unsafe request paths', async () => {
    expect(await validateTarget({ allowedOrigin: 'javascript://example.test' })).not.toBeNull();
    expect(await validateTarget({ allowedOrigin: 'http://user:pass@example.test' })).not.toBeNull();
    expect(await validateTarget({ allowedOrigin: 'http://example.test/private?x=1' })).not.toBeNull();
    for (const path of ['https://other.test/x', '//other.test/x', '/\\\\other.test/x', '/%2f%2fother.test']) {
      expect((await validateUrl(target, path)).ok).toBe(false);
    }
  });

  it('rejects redirects outside the exact configured origin', async () => {
    const current = new URL('http://127.0.0.1:43127/start');
    expect((await validateRedirect(target, 'http://127.0.0.2:43127/next', current)).ok).toBe(false);
    expect((await validateRedirect(target, '/next', current)).ok).toBe(true);
  });

  it('requires explicit private-network opt-in while rejecting metadata', async () => {
    expect(await validateTarget({ allowedOrigin: 'http://10.0.0.4:3000' })).not.toBeNull();
    expect(await validateTarget({ allowedOrigin: 'http://10.0.0.4:3000', allowPrivateNetworkTarget: true })).toBeNull();
    expect(await validateTarget({ allowedOrigin: 'http://169.254.169.254' })).not.toBeNull();
  });
});

describe('Phase 6 request controls and evidence', () => {
  it('redacts sensitive headers and body fields and enforces the response cap', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ token: 'Bearer abcdefghijklmnop', password: 'secret' }), {
      status: 200,
      headers: { 'X-Api-Key': 'key-value', 'X-Trace': 'safe' },
    })));
    const result = await issueRuntimeRequest(
      { ...target, maxResponseBytes: 20 },
      new Map([['user', { id: 'user', kind: 'authenticated', headers: { Authorization: 'Bearer abcdefghijklmnop' } }]]),
      { method: 'GET', path: '/safe', sessionId: 'user' },
      new RuntimeClientState({ ...target, maxResponseBytes: 20 })
    );
    expect(result.response.headers['x-api-key']).toBe('[REDACTED]');
    expect(result.response.bodySnippet).not.toContain('abcdefghijklmnop');
    expect(result.response.bodySnippet).not.toContain('secret');
    expect(result.response.bodyTruncated).toBe(true);
  });

  it('blocks unsafe methods unless the exact path is explicitly vetted', async () => {
    const result = await issueRuntimeRequest(
      { ...target, allowDestructiveMethods: true },
      new Map(),
      { method: 'DELETE', path: '/delete', sessionId: null },
      new RuntimeClientState(target)
    );
    expect(result.response.status).toBe(0);
    expect(result.note).toContain('vettedTestPaths');
  });

  it('enforces the per-case request limit', async () => {
    const limited = { ...target, maxRequestsPerCase: 1 };
    vi.stubGlobal('fetch', vi.fn(async () => new Response('ok', { status: 200 })));
    const state = new RuntimeClientState(limited);
    const sessions = new Map();
    await issueRuntimeRequest(limited, sessions, { method: 'GET', path: '/one', sessionId: null }, state);
    const second = await issueRuntimeRequest(limited, sessions, { method: 'GET', path: '/two', sessionId: null }, state);
    expect(state.requestsIssued).toBe(1);
    expect(second.note).toContain('request limit');
  });
});

describe('Phase 6 orchestration and MCP-facing semantics', () => {
  it('exposes both runtime operations through the MCP response envelope', async () => {
    const listTool = toolDefinitions.find((tool) => tool.name === 'list_verification_cases');
    const verifyTool = toolDefinitions.find((tool) => tool.name === 'verify_finding');
    expect(listTool).toBeDefined();
    expect(verifyTool).toBeDefined();
    const listed = await listTool!.handler(config, {});
    expect(listed.isError).toBe(false);
    const cases = JSON.parse(listed.content[0]!.text);
    expect(Array.isArray(cases)).toBe(true);
    const verified = await verifyTool!.handler(config, { findingId: 'unknown', target });
    expect(verified.isError).toBe(true);
    expect(JSON.parse(verified.content[0]!.text).error).toBe('NOT_FOUND');
  });

  it('returns a structured unknown-finding error', async () => {
    const result = await verifyFinding(config, { findingId: 'does-not-exist', target });
    expect(result).toEqual({
      ok: false,
      error: expect.objectContaining({ code: 'NOT_FOUND' }),
    });
  });

  it('lists cases from Phase 4/5 output and preserves suspected status on blocked runtime verification', async () => {
    const cases = listVerificationCases(config);
    expect(cases.length).toBeGreaterThan(0);
    expect(cases.every((vcase) => vcase.findingId.length > 0)).toBe(true);
    const findingId = cases.find((vcase) => vcase.type === 'missing_authentication')?.findingId;
    expect(findingId).toBeDefined();
    const result = await verifyFinding(config, { findingId: findingId!, target: { allowedOrigin: 'http://10.0.0.4:3000' } });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.result.status).toBe('blocked');
      expect(result.data.finding.status).toBe('suspected');
      expect(result.data.finding.runtimeVerification.status).toBe('blocked');
    }
  });

  it('runs the complete Phase 4 -> Phase 5 -> Phase 6 flow against the local fixture', async () => {
    const child = spawn(process.execPath, ['server.mjs'], {
      cwd: RUNTIME_FIXTURE,
      env: { ...process.env, PORT: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    try {
      const startup = await new Promise<string>((resolve, reject) => {
        child.stdout.once('data', (chunk) => resolve(String(chunk)));
        child.once('error', reject);
        child.once('exit', (code) => {
          if (code !== 0) reject(new Error(`runtime fixture exited before startup (code ${code})`));
        });
      });
      const portMatch = /127\.0\.0\.1:(\d+)/.exec(startup);
      expect(portMatch).not.toBeNull();
      const fixtureOrigin = `http://127.0.0.1:${portMatch![1]}`;
      const cases = listVerificationCases(config);
      const findingId = cases.find((vcase) => vcase.type === 'missing_authentication' && vcase.path === '/admin/reset')?.findingId;
      expect(findingId).toBeDefined();
      const result = await verifyFinding(config, {
        findingId: findingId!,
        target: {
          allowedOrigin: fixtureOrigin,
          allowDestructiveMethods: true,
          vettedTestPaths: ['/admin/reset'],
          minRequestIntervalMs: 0,
        },
      });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.data.verificationCase.path).toBe('/admin/reset');
        expect(result.data.result.status).toBe('inconclusive');
        expect(result.data.result.evidence[0]?.response.status).toBeGreaterThanOrEqual(200);
        expect(result.data.result.evidence[0]?.response.status).toBeLessThan(300);
        expect(result.data.result.evidence[0]?.response.bodySnippet).toContain('reset');
        expect(result.data.finding.status).toBe('suspected');
        expect(result.data.finding.runtimeVerification.status).toBe('inconclusive');
      }
    } finally {
      child.kill();
      await once(child, 'exit').catch(() => undefined);
    }
  });
});
