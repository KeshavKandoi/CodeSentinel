import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { scanProject } from '../../src/security/scanner.js';
import { linkSecurityReceiptToRemediation, proveSecurityFinding, replaySecurityProof, resetSecurityProofsForTests } from '../../src/proof/engine.js';
import { issueRuntimeRequest, RuntimeClientState } from '../../src/runtime/httpClient.js';

const fixture = fs.realpathSync(fileURLToPath(new URL('../fixtures/phase11-runtime', import.meta.url)));
const config: AppConfig = { projectRoot: fixture, commandTimeoutMs: 5_000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
let child: ChildProcess;
let origin = '';

async function waitForServer(port: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    try { const response = await fetch(`http://127.0.0.1:${port}/cors`); if (response.status > 0) return; } catch { /* starting */ }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('Phase 11 fixture did not start');
}

beforeAll(async () => {
  const port = 43891;
  origin = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server.mjs'], { cwd: fixture, env: { ...process.env, PORT: String(port), CODESENTINEL_SECURE: '0' }, stdio: 'ignore' });
  await waitForServer(port);
});

afterAll(() => { child.kill('SIGTERM'); });

describe('Phase 11 real local fixture proofs', () => {
  it('executes semantic vulnerable proofs through the registry and Phase 6 controls', async () => {
    resetSecurityProofsForTests();
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const expected: Record<string, string> = {
      'CS-NODE-016': 'jwt_verification', 'CS-NODE-017': 'session_cookie_flags', 'CS-NODE-018': 'csrf',
      'CS-NODE-019': 'webhook_signature', 'CS-NODE-020': 'mass_assignment', 'CS-NODE-010': 'unrestricted_upload', 'CS-NODE-007': 'permissive_cors',
    };
    for (const [ruleId, proofType] of Object.entries(expected)) {
      const finding = scan.data.findings.find((item) => item.ruleId === ruleId);
      expect(finding, ruleId).toBeDefined();
      if (!finding) continue;
      const unsafe = ['csrf', 'webhook_signature', 'mass_assignment', 'unrestricted_upload'].includes(proofType);
      const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: origin, allowDestructiveMethods: unsafe, vettedTestPaths: unsafe ? ['/transfer', '/webhook', '/profile', '/upload'] : undefined, minRequestIntervalMs: 0 } });
      expect(result.ok, proofType).toBe(true);
      if (result.ok) {
        expect(result.data.proofCase.type).toBe(proofType);
        expect(result.data.status, proofType).toBe('verified');
        expect(JSON.stringify(result.data)).not.toContain('fixture-secret');
      }
    }
  });

  it('reaches secure fixture behavior rather than passing by pre-request blocking', async () => {
    const secureRoot = path.join(fixture, 'secure');
    const secureConfig = { ...config, projectRoot: secureRoot };
    const port = 43892;
    const secureChild = spawn(process.execPath, ['server.mjs'], { cwd: secureRoot, env: { ...process.env, PORT: String(port), CODESENTINEL_SECURE: '1' }, stdio: 'ignore' });
    try {
      await waitForServer(port);
      const target = { allowedOrigin: `http://127.0.0.1:${port}`, allowDestructiveMethods: true, vettedTestPaths: ['/transfer', '/webhook', '/profile', '/upload'], minRequestIntervalMs: 0 };
      const paths: Array<{ path: string; body: string; expected: number }> = [
        { path: '/transfer', body: 'amount=1', expected: 403 }, { path: '/webhook', body: '{}', expected: 401 },
        { path: '/profile', body: 'role=admin', expected: 200 }, { path: '/upload', body: 'filename="a.html"', expected: 415 },
      ];
      for (const item of paths) {
        const evidence = await issueRuntimeRequest(target, new Map(), { method: 'POST', path: item.path, sessionId: null, body: item.body, headers: { origin: 'https://cross-site.invalid' } }, new RuntimeClientState(target));
        expect(evidence.response.status).toBe(item.expected);
        expect(evidence.response.bodySnippet).not.toMatch(/CODESENTINEL_PROOF_(?:CSRF|WEBHOOK|ADMIN|UPLOAD)/);
      }
      const cookie = await issueRuntimeRequest(target, new Map(), { method: 'GET', path: '/session-cookie', sessionId: null }, new RuntimeClientState(target));
      expect(cookie.response.headers['set-cookie']).toContain('httponly');
      expect(cookie.response.headers['set-cookie']).toContain('secure');
      const cors = await issueRuntimeRequest(target, new Map(), { method: 'GET', path: '/cors', sessionId: null }, new RuntimeClientState(target));
      expect(cors.response.headers['access-control-allow-origin']).toBe('https://app.example');
    } finally { secureChild.kill('SIGTERM'); }
    void secureConfig;
  });

  it('replays a persisted CSRF contract against the secure fixture and records the relationship', async () => {
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-018');
    expect(finding).toBeDefined();
    if (!finding) return;
    const target = { allowedOrigin: origin, allowDestructiveMethods: true, vettedTestPaths: ['/transfer'], minRequestIntervalMs: 0 };
    const original = await proveSecurityFinding(config, { findingId: finding.id, target });
    expect(original.ok).toBe(true);
    if (!original.ok) return;
    const remediationId = 'phase11-remediation-csrf';
    const linked = linkSecurityReceiptToRemediation(finding.id, original.data.receiptId, remediationId);
    expect(linked.ok).toBe(true);
    if (!linked.ok) return;
    child.kill('SIGTERM');
    child = spawn(process.execPath, ['server.mjs'], { cwd: path.join(fixture, 'secure'), env: { ...process.env, PORT: '43891', CODESENTINEL_SECURE: '1' }, stdio: 'ignore' });
    await waitForServer(43891);
    const replay = await replaySecurityProof(config, { findingId: finding.id, target, sessions: [], sessionParams: {} }, linked.data, remediationId);
    expect(replay.ok).toBe(true);
    if (!replay.ok) return;
    expect(replay.data.status).toBe('not_reproduced');
    expect(replay.data.replayOfReceiptId).toBe(original.data.receiptId);
    expect(replay.data.remediationRef).toBe(remediationId);
    expect(replay.data.beforeAfter).toEqual({ beforeStatus: 'verified', afterStatus: 'not_reproduced' });
  });
  it('does not verify an invalid-token oracle on a route that is simply public', async () => {
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-016');
    expect(finding).toBeDefined();
    if (!finding) return;
    const http = await import('node:http');
    const server = http.createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('ok'); });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    try {
      const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: `http://127.0.0.1:${port}`, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.status).toBe('inconclusive');
      expect(result.data.whyProven).toBe('');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('records the target origin and execution time on a verified receipt', async () => {
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-016');
    expect(finding).toBeDefined();
    if (!finding) return;
    const port = 43893;
    const ownOrigin = `http://127.0.0.1:${port}`;
    const own = spawn(process.execPath, ['server.mjs'], { cwd: fixture, env: { ...process.env, PORT: String(port), CODESENTINEL_SECURE: '0' }, stdio: 'ignore' });
    try {
      await waitForServer(port);
      const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: ownOrigin, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.status).toBe('verified');
      expect(result.data.targetOrigin).toBe(ownOrigin);
      expect(Number.isNaN(Date.parse(result.data.executedAt ?? ''))).toBe(false);
      expect(result.data.responseFacts.length).toBe(2);
    } finally {
      own.kill('SIGTERM');
    }
  });
  it('verifies the cookie-flag oracle only for a session-like cookie, never an unrelated one', async () => {
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-017');
    expect(finding).toBeDefined();
    if (!finding) return;
    const http = await import('node:http');
    const run = async (cookie: string) => {
      const server = http.createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': cookie }); response.end('ok'); });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      try {
        const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: `http://127.0.0.1:${port}`, minRequestIntervalMs: 0 } });
        expect(result.ok).toBe(true);
        return result.ok ? result.data : null;
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    };
    const unrelated = await run('theme=dark');
    expect(unrelated?.status).toBe('inconclusive');
    expect(unrelated?.whyProven).toBe('');
    const lookalike = await run('sidebar=open');
    expect(lookalike?.status).toBe('inconclusive');
    const session = await run('session=abc123');
    expect(session?.status).toBe('verified');
    expect(JSON.stringify(session)).not.toContain('abc123');
    const secure = await run('session=abc123; Secure; HttpOnly; SameSite=Lax');
    expect(secure?.status).toBe('not_reproduced');
  });
});

describe('Phase 11 insecure deserialization semantic proof', () => {
  const prove = async (secure: boolean, port: number) => {
    resetSecurityProofsForTests();
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return null;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-011');
    expect(finding).toBeDefined();
    if (!finding) return null;
    const proc = spawn(process.execPath, ['server.mjs'], { cwd: fixture, env: { ...process.env, PORT: String(port), CODESENTINEL_SECURE: secure ? '1' : '0' }, stdio: 'ignore' });
    try {
      await waitForServer(port);
      const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: `http://127.0.0.1:${port}`, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      return result.ok ? result.data : null;
    } finally { proc.kill('SIGTERM'); }
  };

  it('verifies the vulnerable fixture only through the semantic marker', async () => {
    const receipt = await prove(false, 43894);
    expect(receipt?.proofCase.type).toBe('insecure_deserialization');
    expect(receipt?.status).toBe('verified');
    expect(receipt?.targetOrigin).toBe('http://127.0.0.1:43894');
    expect(JSON.stringify(receipt)).toContain('CODESENTINEL_PROOF_DESERIALIZED');
    expect(JSON.stringify(receipt)).not.toContain('fixture-secret');
  });

  it('does not verify the secure fixture', async () => {
    const receipt = await prove(true, 43895);
    expect(receipt?.status).toBe('not_reproduced');
    expect(receipt?.whyProven).toBe('');
  });

  it('never verifies a target that merely echoes the probe value', async () => {
    resetSecurityProofsForTests();
    const scan = await scanProject(config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-011');
    expect(finding).toBeDefined();
    if (!finding) return;
    const http = await import('node:http');
    const echo = http.createServer((request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end(decodeURIComponent(request.url ?? '')); });
    await new Promise<void>((resolve) => echo.listen(0, '127.0.0.1', resolve));
    const address = echo.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    try {
      const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: `http://127.0.0.1:${port}`, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.status).not.toBe('verified');
      expect(result.data.whyProven).toBe('');
    } finally {
      await new Promise<void>((resolve) => echo.close(() => resolve()));
    }
  });
});
