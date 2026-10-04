import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { analyzeAccessControl } from '../../src/access/engine.js';
import { discoverRoutes } from '../../src/routes/engine.js';
import { buildSecurityGraph, listSecurityProofAdapters, listSecurityProofCases, proveSecurityFinding, resetSecurityProofsForTests } from '../../src/proof/engine.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';
import { scanProject } from '../../src/security/scanner.js';
import { detachedRedacted } from '../../src/report/redaction.js';
import { validateTarget } from '../../src/runtime/targetGuard.js';
import { runSecurityAuditPipeline } from '../../src/audit/pipeline.js';
import { advance, advanceToVerified, canAdvance } from '../../src/audit/lifecycle.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { listFiles } from '../../src/fs/fsOperations.js';
import type { AuditFinding } from '../../src/audit/types.js';
import { verifyFindingSchema } from '../../src/validation/schemas.js';

const root = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const securityRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
const securityConfig: AppConfig = { ...config, projectRoot: securityRoot };
const vulnerableProofRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable', import.meta.url)));
const secureProofRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/proof-runtime/secure', import.meta.url)));
const vulnerableProofConfig: AppConfig = { ...config, projectRoot: vulnerableProofRoot };
const secureProofConfig: AppConfig = { ...config, projectRoot: secureProofRoot };
let vulnerableProofServer: http.Server;
let secureProofServer: http.Server;
let vulnerableProofOrigin = '';
let secureProofOrigin = '';

function createProofServer(secure: boolean): http.Server {
  return http.createServer((request, response) => {
    const pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
    response.setHeader('authorization', 'Bearer proof-fixture-secret');
    if (secure) {
      response.writeHead(pathname === '/proxy' ? 403 : pathname === '/redirect' || pathname === '/path' ? 400 : 200, { 'content-type': 'text/plain' });
      response.end(pathname === '/hello' ? 'safe escaped response' : 'safe fixture response');
      return;
    }
    if (pathname === '/redirect') {
      response.writeHead(302, { location: 'https://codesentinel.invalid/proof' });
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/plain' });
    const marker = pathname === '/path'
      ? 'CODESENTINEL_PROOF_OUTSIDE_ROOT'
      : pathname === '/proxy'
        ? 'CODESENTINEL_PROOF_SSRF_SENTINEL'
        : pathname === '/search'
          ? 'CODESENTINEL_PROOF_SQLI_SENTINEL'
          : pathname === '/run'
            ? 'CODESENTINEL_PROOF_COMMAND_SENTINEL'
            : 'CODESENTINEL_PROOF_XSS_SENTINEL';
    response.end(marker);
  });
}

async function listen(server: http.Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Proof fixture did not expose a TCP address.');
  return `http://127.0.0.1:${address.port}`;
}

beforeAll(async () => {
  vulnerableProofServer = createProofServer(false);
  secureProofServer = createProofServer(true);
  vulnerableProofOrigin = await listen(vulnerableProofServer);
  secureProofOrigin = await listen(secureProofServer);
});

afterAll(async () => {
  await Promise.all([
    new Promise<void>((resolve, reject) => vulnerableProofServer.close((error) => error ? reject(error) : resolve())),
    new Promise<void>((resolve, reject) => secureProofServer.close((error) => error ? reject(error) : resolve())),
  ]);
});

beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });

describe('security proof engine', () => {
  it('uses an explicit adapter registry for executable proof classes', () => {
    const adapters = listSecurityProofAdapters();
    expect(adapters.map((adapter) => adapter.type)).toEqual(expect.arrayContaining(['idor_bola', 'missing_authentication', 'missing_authorization', 'authorization_inconsistency']));
    expect(adapters.map((adapter) => adapter.type)).toEqual(expect.arrayContaining(['path_traversal', 'open_redirect', 'ssrf', 'sql_injection', 'command_injection', 'xss_reflected']));
    expect(adapters.map((adapter) => adapter.type)).toEqual(expect.arrayContaining(['jwt_verification', 'session_cookie_flags', 'permissive_cors', 'insecure_deserialization']));
  });

  it('lists only proof cases backed by the current route/access inventory', () => {
    const cases = listSecurityProofCases(config);
    expect(cases.length).toBeGreaterThan(0);
    for (const item of cases) {
      expect(item.maxRequests).toBeGreaterThan(0);
      expect(item.allowedMethods.length).toBeGreaterThan(0);
      expect(item.vulnerableOracle).not.toMatch(/status alone/i);
      expect(item.evidenceCaptured.length).toBeGreaterThan(0);
    }
  });

  it('builds graph nodes and evidence-backed route/access edges', () => {
    const graph = buildSecurityGraph(config);
    expect(graph.ok).toBe(true);
    if (!graph.ok) return;
    expect(graph.data.nodes.some((node) => node.kind === 'route')).toBe(true);
    expect(graph.data.edges.every((edge) => edge.evidenceRefs.length > 0)).toBe(true);
  });

  it('returns a blocked receipt when Phase 6 rejects the target', async () => {
    const routes = discoverRoutes(config);
    expect(routes.ok).toBe(true);
    if (!routes.ok) return;
    const access = analyzeAccessControl(config, routes.data.entries);
    const finding = access.findings.find((item) => item.candidateType === 'missing_authentication' || item.candidateType === 'missing_authorization');
    expect(finding).toBeDefined();
    if (!finding) return;
    const result = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: 'http://10.0.0.4:3000' } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.status).toBe('blocked');
    expect(JSON.stringify(result.data)).not.toContain('Authorization');
  });

  it('never fabricates proof for unsupported static categories', async () => {
    const result = await proveSecurityFinding(config, { findingId: 'static-only-finding', target: { allowedOrigin: 'http://10.0.0.4:3000' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('NOT_FOUND');
  });

  it('selects a safe source adapter for a route-backed injection candidate but blocks non-loopback targets', async () => {
    const { scanProject } = await import('../../src/security/scanner.js');
    const scan = await scanProject(securityConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    const result = await proveSecurityFinding(securityConfig, { findingId: finding.id, target: { allowedOrigin: 'http://10.0.0.4:3000' } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.proofCase.type).toBe('sql_injection');
    expect(result.data.status).toBe('blocked');
  });

  it('proves a source-backed SQL injection only when the semantic fixture oracle matches', async () => {
    const scan = await scanProject(securityConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;

    const result = await proveSecurityFinding(securityConfig, { findingId: finding.id, target: { allowedOrigin: vulnerableProofOrigin } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.status).toBe('verified');
    expect(result.data.oracle).toBe('verified');
    expect(result.data.responseFacts[0]?.bodySnippet).toContain('CODESENTINEL_PROOF_SQLI_SENTINEL');
    expect(JSON.stringify(result.data)).not.toContain('Authorization');
    expect(result.data.sourceRefs.length).toBeGreaterThan(0);
    expect(result.data.evidenceRefs).toEqual(expect.arrayContaining([`static:${finding.id}`]));
  });

  it.each([
    ['path_traversal', 'path_traversal', 'CODESENTINEL_PROOF_OUTSIDE_ROOT'],
    ['open_redirect', 'open_redirect', 'https://codesentinel.invalid/proof'],
    ['ssrf', 'ssrf', 'CODESENTINEL_PROOF_SSRF_SENTINEL'],
    ['sql_injection', 'injection', 'CODESENTINEL_PROOF_SQLI_SENTINEL'],
    ['command_injection', 'command_injection', 'CODESENTINEL_PROOF_COMMAND_SENTINEL'],
    ['xss_reflected', 'xss', 'CODESENTINEL_PROOF_XSS_SENTINEL'],
  ])('verifies the vulnerable %s fixture using its semantic oracle', async (proofType, category, marker) => {
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === category);
    expect(finding, `missing ${category} finding`).toBeDefined();
    if (!finding) return;
    const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: finding.id, target: { allowedOrigin: vulnerableProofOrigin } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.proofCase.type).toBe(proofType);
    expect(result.data.status).toBe('verified');
    expect(JSON.stringify(result.data)).toContain(marker);
    expect(JSON.stringify(result.data)).not.toContain('proof-fixture-secret');
    if (proofType === 'open_redirect') expect(result.data.responseFacts[0]?.finalUrl).not.toContain('codesentinel.invalid');
  });

  it.each([
    ['path_traversal', 'path_traversal'],
    ['open_redirect', 'open_redirect'],
    ['ssrf', 'ssrf'],
    ['sql_injection', 'injection'],
    ['command_injection', 'command_injection'],
    ['xss_reflected', 'xss'],
  ])('does not verify the secure %s fixture', async (proofType, category) => {
    const scan = await scanProject(secureProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === category);
    const result = await proveSecurityFinding(secureProofConfig, { findingId: finding?.id ?? `secure-${proofType}`, target: { allowedOrigin: secureProofOrigin } });
    if (!finding) {
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('NOT_FOUND');
      return;
    }
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.status).not.toBe('verified');
    expect(result.data.whyProven).toBe('');
  });

  it('classifies a secure response without the semantic marker as not reproduced', async () => {
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: finding.id, target: { allowedOrigin: secureProofOrigin } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(['not_reproduced', 'inconclusive']).toContain(result.data.status);
  });

  it('fails closed for malformed, non-loopback, missing-prerequisite, and exhausted requests', async () => {
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    for (const target of [
      { allowedOrigin: 'not a URL' },
      { allowedOrigin: 'http://10.0.0.4:3000' },
      { allowedOrigin: vulnerableProofOrigin, maxRequestsPerCase: 0 },
    ]) {
      const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: finding.id, target });
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.data.status).toBe('blocked');
    }
    const missing = await proveSecurityFinding(vulnerableProofConfig, { findingId: 'missing-prerequisite', target: { allowedOrigin: vulnerableProofOrigin } });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error.code).toBe('NOT_FOUND');
  });
  it('never verifies a target that merely echoes the probe value', async () => {
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    const echo = http.createServer((request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end(decodeURIComponent(request.url ?? '')); });
    const origin = await listen(echo);
    try {
      const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: finding.id, target: { allowedOrigin: origin } });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.status).toBe('not_reproduced');
      expect(result.data.whyProven).toBe('');
    } finally {
      await new Promise<void>((resolve) => echo.close(() => resolve()));
    }
  });

  it('enforces a cross-call proof attempt budget per finding', async () => {
    resetSecurityProofsForTests();
    const scanned = await scanProject(vulnerableProofConfig);
    const budgetFinding = scanned.ok ? scanned.data.findings.find((item) => item.category === 'injection') : undefined;
    expect(budgetFinding).toBeDefined();
    let rejected = 0;
    for (let i = 0; i < 12; i++) {
      const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: budgetFinding!.id, target: { allowedOrigin: vulnerableProofOrigin } });
      if (!result.ok && result.error.code === 'BUDGET_EXCEEDED') rejected += 1;
    }
    expect(rejected).toBe(2);
    resetSecurityProofsForTests();
  });
  it('rejects forged, tampered, mismatched, and evidence-free receipts in advanceToVerified', async () => {
    const scan = await scanProject(securityConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    const proven = await proveSecurityFinding(securityConfig, { findingId: finding.id, target: { allowedOrigin: vulnerableProofOrigin } });
    expect(proven.ok).toBe(true);
    if (!proven.ok) return;
    expect(proven.data.status).toBe('verified');
    const make = (adapter: string): AuditFinding => ({
      status: 'proof_eligible',
      classification: { proofSupport: 'runtime', proofStatus: 'eligible', adapter, proofSourceId: finding.id, prerequisites: [], maxRequests: 1, reason: 'test' },
    }) as unknown as AuditFinding;
    const forged = { ...proven.data, receiptId: 'receipt-forged', whyProven: 'manually constructed proof text', proofCase: { ...proven.data.proofCase, executable: true } };
    expect(() => advanceToVerified(make('sql_injection'), forged)).toThrow();
    expect(() => advanceToVerified(make('sql_injection'), { ...proven.data, whyProven: 'tampered explanation of proof' })).toThrow();
    expect(() => advanceToVerified(make('xss_reflected'), proven.data)).toThrow();
    expect(() => advanceToVerified(make('sql_injection'), { ...proven.data, responseFacts: [] })).toThrow();
    const genuine = make('sql_injection');
    advanceToVerified(genuine, proven.data);
    expect(genuine.status).toBe('verified');
  });

  it('rejects non-http origins and malformed vetted paths at the MCP schema boundary', () => {
    const base = { findingId: 'f' };
    expect(verifyFindingSchema.safeParse({ ...base, target: { allowedOrigin: 'javascript:alert(1)' } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ ...base, target: { allowedOrigin: 'file:///etc/passwd' } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ ...base, target: { allowedOrigin: 'http://127.0.0.1:3000', vettedTestPaths: ['//evil'] } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ ...base, target: { allowedOrigin: 'http://127.0.0.1:3000', vettedTestPaths: ['relative'] } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ ...base, target: { allowedOrigin: 'http://127.0.0.1:3000', vettedTestPaths: ['/transfer'] } }).success).toBe(true);
  });
  it('redacts JWTs, PEM keys, URL credentials and embedded secret fields but keeps the inert probe token', () => {
    const out = JSON.stringify(detachedRedacted({
      a: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz123456',
      b: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----',
      c: 'http://admin:hunter2@127.0.0.1:3000/x',
      d: '{"password":"hunter2","api_key":"k-12345678901234"}',
      e: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjb2Rlc2VudGluZWwifQ.invalid-signature',
      f: 'plain evidence text',
    }));
    for (const leaked of ['hunter2', 'abcdefghijklmnopqrstuvwxyz123456', 'MIIEvQ', 'k-12345678901234']) expect(out).not.toContain(leaked);
    expect(out).toContain('invalid-signature');
    expect(out).toContain('plain evidence text');
  });
  it('rejects remote and look-alike hosts but accepts loopback forms', async () => {
    for (const allowedOrigin of ['http://example.com', 'http://93.184.216.34', 'http://127.attacker.com', 'http://localhost.evil.test']) {
      expect(await validateTarget({ allowedOrigin }), allowedOrigin).not.toBeNull();
    }
    for (const allowedOrigin of ['http://127.0.0.1:3000', 'http://localhost:3000', 'http://[::1]:3000']) {
      expect(await validateTarget({ allowedOrigin }), allowedOrigin).toBeNull();
    }
  });

  it('returns blocked, never verified, for a closed target and a remote target', async () => {
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    for (const allowedOrigin of ['http://127.0.0.1:1', 'http://127.attacker.com:3000']) {
      const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: finding.id, target: { allowedOrigin, requestTimeoutMs: 1000, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      if (result.ok) { expect(result.data.status).toBe('blocked'); expect(result.data.whyProven).toBe(''); }
    }
  });
  it('never produces a verified finding from an audit with no target or a remote target', async () => {
    for (const target of [undefined, { allowedOrigin: 'http://127.attacker.com:3000', requestTimeoutMs: 1000, minRequestIntervalMs: 0 }]) {
      const result = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, ...(target ? { target } : {}) });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.findings.length).toBeGreaterThan(0);
      for (const finding of result.data.findings) {
        expect(finding.status).not.toBe('verified');
        expect(finding.proof.status).not.toBe('verified');
        expect(finding.proof.fromPriorReceipt === false || finding.proof.status !== 'verified').toBe(true);
      }
    }
  });
  it('enforces maxProofAttempts at 1, 5 and a large limit', async () => {
    const attemptedAt = async (limit: number) => {
      resetSecurityProofsForTests();
      const result = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, maxProofAttempts: limit, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      if (!result.ok) return -1;
      return result.data.findings.filter((finding) => finding.proof.attempted).length;
    };
    const one = await attemptedAt(1);
    const five = await attemptedAt(5);
    const large = await attemptedAt(100);
    expect(one).toBe(1);
    expect(five).toBeLessThanOrEqual(5);
    expect(large).toBeGreaterThanOrEqual(five);
    expect(large).toBeGreaterThan(1);
    resetSecurityProofsForTests();
  }, 120_000);

  it('produces stable finding ids, classifications and proof statuses across repeated audits', async () => {
    const signature = async () => {
      resetSecurityProofsForTests();
      const result = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
      expect(result.ok).toBe(true);
      if (!result.ok) return '';
      const rows = result.data.findings.map((finding) => ({ id: finding.id, status: finding.status, support: finding.classification.proofSupport, classStatus: finding.classification.proofStatus, adapter: finding.classification.adapter, proof: finding.proof.status })).sort((a, b) => a.id.localeCompare(b.id));
      return JSON.stringify({ rows, total: result.data.summary.total, byStatus: result.data.summary.byStatus });
    };
    const first = await signature();
    const second = await signature();
    expect(first.length).toBeGreaterThan(0);
    expect(second).toBe(first);
    resetSecurityProofsForTests();
  }, 120_000);

  it('only reaches verified through a runtime receipt and never for static-only findings', async () => {
    resetSecurityProofsForTests();
    const result = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const verified = result.data.findings.filter((finding) => finding.status === 'verified');
    expect(verified.length).toBeGreaterThan(0);
    for (const finding of verified) {
      expect(finding.classification.proofSupport).toBe('runtime');
      expect(finding.proof.status).toBe('verified');
      expect(finding.proof.receiptIds.length).toBeGreaterThan(0);
    }
    for (const finding of result.data.findings.filter((item) => item.classification.proofSupport !== 'runtime')) expect(finding.status).not.toBe('verified');
    resetSecurityProofsForTests();
  }, 60_000);

  it('allows only the supported lifecycle transitions', () => {
    expect(canAdvance('candidate', 'analyzed')).toBe(true);
    expect(canAdvance('analyzed', 'proof_eligible')).toBe(true);
    for (const to of ['verified', 'not_reproduced', 'inconclusive', 'blocked'] as const) expect(canAdvance('proof_eligible', to)).toBe(true);
    expect(canAdvance('verified', 'remediation_applied')).toBe(true);
    expect(canAdvance('remediation_applied', 'verified_resolved')).toBe(true);
    expect(canAdvance('candidate', 'verified')).toBe(false);
    expect(canAdvance('analyzed', 'verified')).toBe(false);
    for (const to of ['verified', 'proof_eligible', 'not_reproduced', 'blocked', 'inconclusive', 'analyzed'] as const) expect(canAdvance('unsupported', to)).toBe(false);
    for (const from of ['not_reproduced', 'blocked', 'inconclusive'] as const) expect(canAdvance(from, 'verified')).toBe(false);
    expect(() => advance({ status: 'unsupported' } as unknown as AuditFinding, 'verified')).toThrow();
  });

  it('rejects unknown arguments on the audit and proof MCP tools', async () => {
    for (const name of ['run_full_security_audit', 'prove_security_finding']) {
      const tool = toolDefinitions.find((item) => item.name === name);
      expect(tool, name).toBeDefined();
      const response = await tool!.handler(securityConfig, { findingId: 'x', target: { allowedOrigin: 'http://127.0.0.1:3000' }, bogusArgument: true });
      expect(response.isError, name).toBe(true);
    }
  });
});

describe('Phase 9 audit hardening', () => {
  it('does not reuse a verified receipt from a different target origin', async () => {
    resetSecurityProofsForTests();
    const first = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
    if (!first.ok) throw new Error('first audit failed');
    expect(first.data.summary.runtimeVerified).toBeGreaterThan(0);
    const second = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, target: { allowedOrigin: secureProofOrigin, minRequestIntervalMs: 0 } });
    if (!second.ok) throw new Error('second audit failed');
    expect(second.data.summary.runtimeVerified).toBe(0);
    expect(second.data.findings.every((finding) => finding.status !== 'verified')).toBe(true);
    resetSecurityProofsForTests();
  }, 60000);

  it('produces identical normalized audit output across repeated runs', async () => {
    resetSecurityProofsForTests();
    const normalize = (data: any) => JSON.stringify({
      auditId: data.auditId,
      summary: data.summary,
      findings: data.findings.map((f: any) => ({ id: f.id, status: f.status, severity: f.severity, riskScore: f.riskScore, evidence: f.evidence, evidenceSynthesis: f.evidenceSynthesis, sources: f.sources, correlation: f.correlation })),
      nearDuplicates: data.nearDuplicates,
      graph: { nodes: data.graph.nodes, edges: data.graph.edges, nodeKinds: data.graph.nodeKinds, edgeRelations: data.graph.edgeRelations },
    });
    const runs: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      const result = await runSecurityAuditPipeline(securityConfig, { sessions: [], sessionParams: {}, includeGraph: true });
      if (!result.ok) throw new Error('audit failed');
      runs.push(normalize(result.data));
    }
    expect(runs[1]).toBe(runs[0]);
    expect(runs[2]).toBe(runs[0]);
  }, 60000);
});

describe('Phase 9 runtime client bounds', () => {
  it('ends a stalled response body at the request timeout instead of hanging', async () => {
    const { issueRuntimeRequest, RuntimeClientState } = await import('../../src/runtime/httpClient.js');
    const stalled = http.createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.write('x');
    });
    const origin = await listen(stalled);
    try {
      const target = { allowedOrigin: origin, requestTimeoutMs: 300, minRequestIntervalMs: 0 };
      const started = Date.now();
      const evidence = await issueRuntimeRequest(target, new Map(), { method: 'GET', path: '/', sessionId: null }, new RuntimeClientState(target));
      expect(Date.now() - started).toBeLessThan(5000);
      expect(evidence.response.bodyTruncated).toBe(true);
    } finally {
      stalled.closeAllConnections();
      await new Promise<void>((resolve) => stalled.close(() => resolve()));
    }
  }, 15000);
});

describe('Phase 9 lifecycle invariants', () => {
  it('never promotes terminal states and never reaches verified without proof_eligible', async () => {
    const { FINDING_STATUSES } = await import('../../src/audit/types.js');
    for (const terminal of ['not_reproduced', 'unsupported', 'blocked', 'inconclusive', 'verified_resolved'] as const) {
      for (const next of FINDING_STATUSES) expect(canAdvance(terminal, next), `${terminal} -> ${next}`).toBe(false);
    }
    expect(canAdvance('candidate', 'verified')).toBe(false);
    expect(canAdvance('analyzed', 'verified')).toBe(false);
    expect(canAdvance('unsupported', 'verified')).toBe(false);
    expect(canAdvance('proof_eligible', 'verified')).toBe(true);
  });
});

describe('Phase 9 unknown finding id', () => {
  it('returns NOT_FOUND without consuming proof budget or creating a receipt', async () => {
    resetSecurityProofsForTests();
    const { listSecurityReceiptsForFinding } = await import('../../src/proof/engine.js');
    for (let i = 0; i < 15; i++) {
      const result = await proveSecurityFinding(config, { findingId: 'no-such-finding', target: { allowedOrigin: 'http://127.0.0.1:1' } });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('NOT_FOUND');
    }
    expect(listSecurityReceiptsForFinding('no-such-finding')).toHaveLength(0);
    resetSecurityProofsForTests();
  });
});

describe('Phase 9 redaction coverage', () => {
  const secrets: Array<[string, string]> = [
    ['sent Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ+x/y== here', 'x/y'],
    ['token ghs_16C7e42F292c6912E7710c838347Ae178B4a', '16C7e42F'],
    ['github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789', '11ABCDEFG0'],
    ['AIzaSyA1234567890abcdefghijklmnopqrstuv', 'A1234567890'],
    ['eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.', 'eyJzdWIi'],
    ['Authorization: abcdef123456secret', 'abcdef123456'],
    ['Proxy-Authorization: Basic dXNlcjpwYXNz', 'dXNlcjpw'],
    ['https://abcd1234efgh5678@github.com/org/repo.git', 'abcd1234efgh5678'],
    ['postgres://admin:hunter2pass@db.local:5432/app', 'hunter2pass'],
    ['AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', 'wJalrXUtn'],
    ['auth_token=abcd1234efgh5678', 'abcd1234efgh'],
    ['private_key: "abcd1234efgh5678"', 'abcd1234efgh'],
    ['Cookie: sid=abc123def456; theme=dark', 'abc123def456'],
    ['Set-Cookie: session=s3cr3tvalue; HttpOnly', 's3cr3tvalue'],
    ['{"password":"Sup3rS3cret!"}', 'Sup3rS3cret'],
  ];
  it.each(secrets)('redacts %s', (input, fragment) => {
    expect(JSON.stringify(detachedRedacted({ text: input }))).not.toContain(fragment);
  });
  it('keeps benign security evidence readable', () => {
    for (const text of ['Missing Authorization header on GET /admin', 'Basic authentication is required', 'Route /users/:id lacks an ownership check', 'token validation is skipped', 'Cookie flags are missing HttpOnly', 'secret rotation is not configured']) {
      expect(detachedRedacted({ text }).text).toBe(text);
    }
  });
});

describe('Phase 9 write oracle stability', () => {
  type RuntimeTargetType = import('../../src/runtime/types.js').RuntimeTarget;
  const makeCase = (method: string, path: string) => ({ id: 'VC-STABILITY', type: 'method_authorization', findingId: 'f', routeId: 'r', method, path, framework: 'express', objective: 'o', preconditions: [], requiredSessions: [], expectedSecureBehavior: 'e', cleanupRequired: false, relatedCandidateType: 'inconsistent_authorization' }) as unknown as import('../../src/runtime/types.js').VerificationCase;
  it('does not verify a write whose only observable change is a volatile read field', async () => {
    const { runMethodAuthorizationCase } = await import('../../src/runtime/cases/methodAuthorization.js');
    const { RuntimeClientState } = await import('../../src/runtime/httpClient.js');
    let reads = 0;
    const server = http.createServer((request, response) => {
      if (request.method === 'GET') { reads += 1; response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ name: 'a', ts: reads })); return; }
      response.writeHead(200); response.end('ok');
    });
    const origin = await listen(server);
    try {
      const target: RuntimeTargetType = { allowedOrigin: origin, minRequestIntervalMs: 0, allowDestructiveMethods: true, vettedTestPaths: ['/item'] };
      const result = await runMethodAuthorizationCase(makeCase('POST', '/item'), target, new Map(), new RuntimeClientState(target));
      expect(result.status, result.summary).toBe('inconclusive');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
  it('still verifies a write that changes stable state', async () => {
    const { runMethodAuthorizationCase } = await import('../../src/runtime/cases/methodAuthorization.js');
    const { RuntimeClientState } = await import('../../src/runtime/httpClient.js');
    let name = 'a';
    const server = http.createServer((request, response) => {
      if (request.method === 'GET') { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ name })); return; }
      name = 'b'; response.writeHead(200); response.end('ok');
    });
    const origin = await listen(server);
    try {
      const target: RuntimeTargetType = { allowedOrigin: origin, minRequestIntervalMs: 0, allowDestructiveMethods: true, vettedTestPaths: ['/item'] };
      const result = await runMethodAuthorizationCase(makeCase('POST', '/item'), target, new Map(), new RuntimeClientState(target));
      expect(result.status, result.summary).toBe('verified');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe('Phase 9 receipt origin isolation', () => {
  const makeFinding = (adapter: string, sourceId: string): AuditFinding => ({
    status: 'proof_eligible',
    classification: { proofSupport: 'runtime', proofStatus: 'eligible', adapter, proofSourceId: sourceId, prerequisites: [], maxRequests: 1, reason: 'test' },
  }) as unknown as AuditFinding;

  async function proveInjection() {
    resetSecurityProofsForTests();
    const scan = await scanProject(securityConfig);
    if (!scan.ok) throw new Error('scan failed');
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    if (!finding) throw new Error('no injection finding');
    const proven = await proveSecurityFinding(securityConfig, { findingId: finding.id, target: { allowedOrigin: vulnerableProofOrigin } });
    if (!proven.ok) throw new Error('proof failed');
    expect(proven.data.status).toBe('verified');
    expect(proven.data.targetOrigin).toBe(vulnerableProofOrigin);
    return { finding, receipt: proven.data };
  }

  it('accepts a receipt for the origin it was created for', async () => {
    const { finding, receipt } = await proveInjection();
    const target = makeFinding('sql_injection', finding.id);
    advanceToVerified(target, receipt, vulnerableProofOrigin);
    expect(target.status).toBe('verified');
  });

  it('rejects a receipt for a different expected origin', async () => {
    const { finding, receipt } = await proveInjection();
    const target = makeFinding('sql_injection', finding.id);
    expect(() => advanceToVerified(target, receipt, secureProofOrigin)).toThrow();
    expect(target.status).toBe('proof_eligible');
  });

  it('rejects a receipt stripped of its origin whether or not an origin is expected', async () => {
    const { finding, receipt } = await proveInjection();
    const stripped = { ...receipt, targetOrigin: undefined };
    expect(() => advanceToVerified(makeFinding('sql_injection', finding.id), stripped, vulnerableProofOrigin)).toThrow();
    expect(() => advanceToVerified(makeFinding('sql_injection', finding.id), stripped)).toThrow();
  });

  it('rejects a receipt whose origin was forged to match the expected origin', async () => {
    const { finding, receipt } = await proveInjection();
    const forged = { ...receipt, targetOrigin: secureProofOrigin };
    expect(() => advanceToVerified(makeFinding('sql_injection', finding.id), forged, secureProofOrigin)).toThrow();
    expect(() => advanceToVerified(makeFinding('sql_injection', finding.id), forged)).toThrow();
  });

  it('rejects replaying a bound receipt against another origin without storing a new receipt', async () => {
    const { linkSecurityReceiptToRemediation, replaySecurityProof, listSecurityReceiptsForFinding } = await import('../../src/proof/engine.js');
    const { finding, receipt } = await proveInjection();
    const linked = linkSecurityReceiptToRemediation(finding.id, receipt.receiptId, 'rem-origin-test');
    expect(linked.ok).toBe(true);
    if (!linked.ok) return;
    const crossed = await replaySecurityProof(securityConfig, { findingId: finding.id, target: { allowedOrigin: secureProofOrigin, minRequestIntervalMs: 0 }, sessions: [], sessionParams: {} }, linked.data, 'rem-origin-test');
    expect(crossed.ok).toBe(false);
    if (!crossed.ok) expect(crossed.error.message).toMatch(/target origin/);
    expect(listSecurityReceiptsForFinding(finding.id).every((item) => item.targetOrigin === vulnerableProofOrigin)).toBe(true);
  });
});

describe('Phase 9 blocked and budget-limited results', () => {
  it('blocks access-control proofs for their exact prerequisite reasons without sending requests or verifying', async () => {
    resetSecurityProofsForTests();
    const result = await runSecurityAuditPipeline(config, { sessions: [], sessionParams: {}, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const blocked = result.data.findings.filter((finding) => finding.status === 'blocked');
    expect(blocked.length).toBe(3);
    const notes = blocked.map((finding) => `${finding.classification.adapter}:${finding.proof.note}`);
    expect(notes.filter((note) => note.startsWith('missing_authentication:') && /allowDestructiveMethods.*vettedTestPaths/.test(note)).length).toBe(1);
    expect(notes.filter((note) => note.startsWith('idor_bola:') && /ownerSessionId, otherSessionId/.test(note)).length).toBe(2);
    for (const finding of blocked) {
      expect(finding.proof.status).toBe('blocked');
      expect(finding.proof.status).not.toBe('verified');
    }
    expect(result.data.findings.some((finding) => finding.status === 'verified')).toBe(false);
    resetSecurityProofsForTests();
  }, 60_000);

  it('skips exactly the over-budget eligible finding at the default limit and proves it when budget allows', async () => {
    resetSecurityProofsForTests();
    const limited = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
    expect(limited.ok).toBe(true);
    if (!limited.ok) return;
    const skipped = limited.data.findings.filter((finding) => finding.status === 'proof_eligible');
    expect(skipped.length).toBe(1);
    expect(skipped[0].classification.adapter).toBe('open_redirect');
    expect(skipped[0].proof.attempted).toBe(false);
    const issue = limited.data.issues.find((item) => item.code === 'PROOF_ATTEMPT_LIMIT');
    expect(issue?.affectedFindings).toEqual([skipped[0].id]);
    expect(limited.data.findings.filter((finding) => finding.status === 'verified').length).toBe(5);
    resetSecurityProofsForTests();
    const full = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, maxProofAttempts: 100, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } });
    expect(full.ok).toBe(true);
    if (!full.ok) return;
    expect(full.data.findings.find((finding) => finding.classification.adapter === 'open_redirect')?.status).toBe('verified');
    expect(full.data.issues.some((item) => item.code === 'PROOF_ATTEMPT_LIMIT')).toBe(false);
    resetSecurityProofsForTests();
  }, 120_000);
});

describe('Phase 9 secure and inconclusive end-to-end proofs', () => {
  it('runs every runtime-capable finding against the secure server and ends not_reproduced, never verified', async () => {
    resetSecurityProofsForTests();
    const result = await runSecurityAuditPipeline(vulnerableProofConfig, { sessions: [], sessionParams: {}, maxProofAttempts: 100, target: { allowedOrigin: secureProofOrigin, minRequestIntervalMs: 0 } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const runtime = result.data.findings.filter((finding) => finding.classification.proofSupport === 'runtime');
    expect(runtime.length).toBe(6);
    for (const finding of runtime) {
      expect(finding.proof.attempted, String(finding.classification.adapter)).toBe(true);
      expect(finding.status, String(finding.classification.adapter)).toBe('not_reproduced');
      expect(finding.proof.status).toBe('not_reproduced');
      expect(finding.proof.receiptIds.length).toBeGreaterThan(0);
    }
    expect(result.data.findings.some((finding) => finding.status === 'verified' || finding.proof.status === 'verified')).toBe(false);
    expect(result.data.summary.runtimeVerified).toBe(0);
    resetSecurityProofsForTests();
  }, 120_000);

  it('returns inconclusive from the real proof engine when a public route cannot establish a protected baseline', async () => {
    resetSecurityProofsForTests();
    const phase11Root = fs.realpathSync(fileURLToPath(new URL('../fixtures/phase11-runtime', import.meta.url)));
    const phase11Config: AppConfig = { ...config, projectRoot: phase11Root };
    const scan = await scanProject(phase11Config);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.ruleId === 'CS-NODE-016');
    expect(finding).toBeDefined();
    if (!finding) return;
    const publicServer = http.createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('ok'); });
    const publicOrigin = await listen(publicServer);
    try {
      const target = { allowedOrigin: publicOrigin, minRequestIntervalMs: 0 };
      const result = await proveSecurityFinding(phase11Config, { findingId: finding.id, target });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.status).toBe('inconclusive');
      expect(result.data.oracle).toBe('inconclusive');
      expect(result.data.whyProven).toBe('');
      expect(result.data.limitation).toMatch(/protected baseline/);
      expect(result.data.responseFacts.length).toBeGreaterThan(0);
      const lifecycleFinding = { status: 'proof_eligible', classification: { proofSupport: 'runtime', proofStatus: 'eligible', adapter: 'jwt_verification', proofSourceId: finding.id, prerequisites: [], maxRequests: 2, reason: 'test' } } as unknown as AuditFinding;
      expect(() => advanceToVerified(lifecycleFinding, result.data, publicOrigin)).toThrow();
      expect(lifecycleFinding.status).toBe('proof_eligible');
      let accepted = 1;
      for (let index = 0; index < 20; index++) {
        const next = await proveSecurityFinding(phase11Config, { findingId: finding.id, target });
        if (!next.ok) { expect(next.error.code).toBe('BUDGET_EXCEEDED'); break; }
        expect(next.data.status).toBe('inconclusive');
        accepted += 1;
      }
      expect(accepted).toBe(10);
    } finally {
      await new Promise<void>((resolve) => publicServer.close(() => resolve()));
      resetSecurityProofsForTests();
    }
  }, 120_000);
});

describe('Phase 9 sensitive value redaction boundary', () => {
  const forbidden = ['abcdef1234567890', 'abc123def456ghi789', 'dXNlcjpwYXNz', 'c2lnbmF0dXJlMTIzNDU2', 'hunter2', 'fixturecookie123', 'fixture-secret', 'tok-abc123', 'p4ss', 'MIIBOgIBAAJBAKj34'];
  const leakBody = 'CODESENTINEL_PROOF_XSS_SENTINEL sk_live_abcdef1234567890 Bearer abc123def456ghi789 Basic dXNlcjpwYXNz eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMxMjMifQ.c2lnbmF0dXJlMTIzNDU2 postgres://admin:hunter2@db.local/app Cookie: sid=fixturecookie123 api_secret=fixture-secret {"token":"tok-abc123","password":"p4ss"} -----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----';

  it.each([
    ['bare unpadded Basic credential', 'sent Basic dXNlcjpwYXNz here', 'dXNlcjpwYXNz'],
    ['padded Basic credential', 'sent Basic dXNlcjpwYXNzd29yZA== here', 'dXNlcjpwYXNzd29yZA'],
    ['Authorization Basic header', 'Authorization: Basic dXNlcjpwYXNz', 'dXNlcjpwYXNz'],
    ['JSON token field', '{"token":"tok-abc123","ok":true}', 'tok-abc123'],
    ['JSON access token field', '{"access_token":"tok-abc123"}', 'tok-abc123'],
    ['JSON password and secret fields', '{"password":"p4ss","secret":"s3cr3t"}', 'p4ss'],
    ['sk_live key', 'key sk_live_abcdef1234567890 end', 'abcdef1234567890'],
    ['JWT', 'tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMxMjMifQ.c2lnbmF0dXJlMTIzNDU2 end', 'c2lnbmF0dXJlMTIzNDU2'],
    ['Bearer', 'sent Bearer abc123def456ghi789 here', 'abc123def456ghi789'],
    ['URL credentials', 'connect postgres://admin:hunter2@db.local/app', 'hunter2'],
    ['Cookie header', 'Cookie: sid=fixturecookie123; theme=dark', 'fixturecookie123'],
    ['Set-Cookie header', 'Set-Cookie: sid=fixturecookie123; HttpOnly', 'fixturecookie123'],
    ['PEM private key', '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----', 'MIIBOgIBAAJBAKj34'],
    ['keyed fixture-secret', 'api_secret=fixture-secret&x=1', 'fixture-secret'],
  ])('redacts %s', (_label, input, secret) => {
    expect(JSON.stringify(detachedRedacted(input))).not.toContain(secret);
  });

  it('does not redact ordinary prose that merely mentions Basic authentication', () => {
    expect(detachedRedacted('Basic authentication is not used here')).toBe('Basic authentication is not used here');
  });

  it('never returns sensitive response content through the prove_security_finding tool', async () => {
    resetSecurityProofsForTests();
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'xss');
    expect(finding).toBeDefined();
    if (!finding) return;
    const leakServer = http.createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': 'connect.sid=fixturecookie123; HttpOnly', 'x-api-key': 'sk_live_abcdef1234567890', authorization: 'Basic dXNlcjpwYXNz' });
      response.end(leakBody);
    });
    const leakOrigin = await listen(leakServer);
    try {
      const tool = toolDefinitions.find((item) => item.name === 'prove_security_finding');
      expect(tool).toBeDefined();
      if (!tool) return;
      const response = await tool.handler(vulnerableProofConfig, { findingId: finding.id, target: { allowedOrigin: leakOrigin, minRequestIntervalMs: 0 } });
      const text = JSON.stringify(response);
      expect(text).toContain('receipt-');
      for (const secret of forbidden) expect(text, secret).not.toContain(secret);
    } finally {
      await new Promise<void>((resolve) => leakServer.close(() => resolve()));
      resetSecurityProofsForTests();
    }
  });
});

describe('Phase 9 logger redaction and concurrent proof budget', () => {
  it('redacts Bearer, JWT, Basic and URL credentials in free-form log fields', async () => {
    const { vi } = await import('vitest');
    const { logger } = await import('../../src/logger.js');
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      logger.error('probe', { message: 'failed Bearer abc123def456ghi789 Basic dXNlcjpwYXNz eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMxMjMifQ.c2lnbmF0dXJlMTIzNDU2 postgres://admin:hunter2@db.local/app' });
      const written = spy.mock.calls.map((call) => String(call[0])).join('');
      expect(written).toContain('probe');
      for (const secret of ['abc123def456ghi789', 'dXNlcjpwYXNz', 'c2lnbmF0dXJlMTIzNDU2', 'hunter2']) expect(written).not.toContain(secret);
    } finally { spy.mockRestore(); }
  });

  it('never exceeds the per-finding proof budget under concurrent calls', async () => {
    resetSecurityProofsForTests();
    const scan = await scanProject(vulnerableProofConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'xss');
    expect(finding).toBeDefined();
    if (!finding) return;
    const results = await Promise.all(Array.from({ length: 30 }, () => proveSecurityFinding(vulnerableProofConfig, { findingId: finding.id, target: { allowedOrigin: vulnerableProofOrigin, minRequestIntervalMs: 0 } })));
    const accepted = results.filter((item) => item.ok).length;
    const rejected = results.filter((item) => !item.ok);
    expect(accepted).toBe(10);
    expect(rejected.length).toBe(20);
    for (const item of rejected) if (!item.ok) expect(item.error.code).toBe('BUDGET_EXCEEDED');
    resetSecurityProofsForTests();
  }, 120_000);
});

describe('Phase 9 global proof budget under concurrency', () => {
  it('accepts exactly 500 concurrent attempts across findings and rejects every later call', async () => {
    resetSecurityProofsForTests();
    const names = ['access-control-express', 'security-cases', 'phase11-runtime', 'phase11-runtime/secure', 'proof-runtime/vulnerable', 'proof-runtime/secure', 'express-routes', 'fastify-routes', 'nestjs-routes', 'nextjs-routes', 'django-routes', 'fastapi-routes', 'express-ts', 'nextjs-app', 'generic-node'];
    const pool = new Map<string, AppConfig>();
    for (const name of names) {
      const projectRoot = fs.realpathSync(fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url)));
      const cfg: AppConfig = { ...config, projectRoot };
      const scan = await scanProject(cfg);
      if (scan.ok) for (const item of scan.data.findings) if (!pool.has(item.id)) pool.set(item.id, cfg);
      const routes = discoverRoutes(cfg);
      if (routes.ok) for (const item of analyzeAccessControl(cfg, routes.data.entries).findings) if (!pool.has(item.id)) pool.set(item.id, cfg);
    }
    expect(pool.size, 'distinct known findings available').toBeGreaterThanOrEqual(51);
    const pairs = [...pool.entries()];
    const target = { allowedOrigin: 'http://127.attacker.com:3000', minRequestIntervalMs: 0 };
    let accepted = 0;
    for (let start = 0; start < pairs.length; start += 10) {
      const batch = pairs.slice(start, start + 10).flatMap(([id, cfg]) => Array.from({ length: 12 }, () => proveSecurityFinding(cfg, { findingId: id, target })));
      const results = await Promise.all(batch);
      for (const item of results) {
        if (item.ok) { accepted += 1; expect(item.data.status).not.toBe('verified'); }
        else expect(item.error.code).toBe('BUDGET_EXCEEDED');
      }
    }
    expect(accepted).toBe(500);
    for (const [id, cfg] of pairs.slice(0, 5)) {
      const late = await proveSecurityFinding(cfg, { findingId: id, target });
      expect(late.ok).toBe(false);
      if (!late.ok) expect(late.error.code).toBe('BUDGET_EXCEEDED');
    }
    resetSecurityProofsForTests();
  }, 280_000);
});

describe('Phase 9 resource-limit battery', () => {
  it('truncates oversized strings, arrays and depth in the shared redactor', () => {
    expect(String(detachedRedacted('a'.repeat(1_000_000))).length).toBeLessThanOrEqual(2_000);
    expect((detachedRedacted(Array.from({ length: 5_000 }, (_, i) => i)) as number[]).length).toBeLessThanOrEqual(1_000);
    let nested: unknown = 'leaf';
    for (let i = 0; i < 30; i++) nested = { child: nested };
    expect(JSON.stringify(detachedRedacted(nested))).toContain('[TRUNCATED]');
  });

  it('rejects over-long ids, origins, session lists and token-bearing oversized values at the schema boundary', () => {
    const target = { allowedOrigin: vulnerableProofOrigin };
    expect(verifyFindingSchema.safeParse({ findingId: 'f'.repeat(257), target }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ findingId: 'f', target: { allowedOrigin: `http://127.0.0.1:1/${'a'.repeat(600)}` } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ findingId: 'f', target, sessions: Array.from({ length: 11 }, (_, i) => ({ id: `s${i}`, headers: {} })) }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ findingId: 'f', target: { ...target, maxRequestsPerCase: 51 } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ findingId: 'f', target: { ...target, maxResponseBytes: 5_000_001 } }).success).toBe(false);
    expect(verifyFindingSchema.safeParse({ findingId: 'f', target: { ...target, requestTimeoutMs: 30_001 } }).success).toBe(false);
  });

  it('keeps scanning, routing, auditing, listing and reading bounded and deterministic on an oversized project', async () => {
    const os = await import('node:os');
    const nodePath = await import('node:path');
    const dir = fs.realpathSync(fs.mkdtempSync(nodePath.join(os.tmpdir(), 'cs-limits-')));
    try {
      fs.writeFileSync(nodePath.join(dir, 'package.json'), JSON.stringify({ name: 'limits', dependencies: { express: '4.0.0' } }));
      fs.mkdirSync(nodePath.join(dir, 'src'));
      const routes = Array.from({ length: 1_500 }, (_, i) => `app.get('/r${i}', (req, res) => res.send(String(req.query.q)));`).join('\n');
      fs.writeFileSync(nodePath.join(dir, 'src', 'app.js'), `const express = require('express');\nconst app = express();\n${routes}\nmodule.exports = app;\n`);
      fs.writeFileSync(nodePath.join(dir, 'src', 'long.js'), `const x = "${'a'.repeat(3_000_000)}";\n`);
      fs.writeFileSync(nodePath.join(dir, 'big.txt'), 'b'.repeat(3_000_000));
      fs.mkdirSync(nodePath.join(dir, 'many'));
      for (let i = 0; i < 2_500; i++) fs.writeFileSync(nodePath.join(dir, 'many', `f${i}.js`), `module.exports = ${i};\n`);
      const cfg: AppConfig = { projectRoot: dir, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };

      const listed = listFiles(cfg, { dirPath: '.', recursive: true, maxResults: 10_000 });
      expect(listed.ok).toBe(true);
      if (listed.ok) expect(listed.data.length).toBeLessThanOrEqual(2_000);

      const readTool = toolDefinitions.find((item) => item.name === 'read_file');
      for (const input of [{ path: 'big.txt' }, { path: 'big.txt', maxBytes: 10_000_000 }]) {
        const big = await readTool!.handler(cfg, input);
        expect(big.isError).not.toBe(true);
        const payload = JSON.parse(big.content[0].text) as { content: string; sizeBytes: number; truncated: boolean };
        expect(payload.truncated).toBe(true);
        expect(payload.sizeBytes).toBe(3_000_000);
        expect(Buffer.byteLength(payload.content)).toBeLessThanOrEqual(2_000_000);
      }
      const small = await readTool!.handler(cfg, { path: 'big.txt', maxBytes: 1_000 });
      expect(Buffer.byteLength((JSON.parse(small.content[0].text) as { content: string }).content)).toBeLessThanOrEqual(1_000);

      const run = async () => {
        const scan = await scanProject(cfg);
        expect(scan.ok).toBe(true);
        const found = discoverRoutes(cfg);
        expect(found.ok).toBe(true);
        const audit = await runSecurityAuditPipeline(cfg, { sessions: [], sessionParams: {} });
        expect(audit.ok).toBe(true);
        if (!scan.ok || !found.ok || !audit.ok) throw new Error('limit run failed');
        expect(audit.data.findings.length).toBeLessThanOrEqual(5_000);
        expect(JSON.stringify(audit.data).length).toBeLessThan(20_000_000);
        expect(JSON.stringify(scan.data).length).toBeLessThan(20_000_000);
        expect(JSON.stringify(found.data).length).toBeLessThan(20_000_000);
        expect(audit.data.findings.some((finding) => finding.status === 'verified')).toBe(false);
        return JSON.stringify({ scan: scan.data.findings.map((item) => item.id), routes: found.data.entries.map((item) => item.id), audit: audit.data.findings.map((item) => `${item.id}:${item.status}`) });
      };
      const started = Date.now();
      const first = await run();
      const second = await run();
      expect(second).toBe(first);
      expect(Date.now() - started).toBeLessThan(100_000);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});

describe('Phase 9 Digest credential redaction', () => {
  it('redacts the full Digest authorization value and keeps benign header text readable', () => {
    const out = JSON.stringify(detachedRedacted('Authorization: Digest username="bob", realm="r", response="abcdef0123456789abcdef"\nAccess-Control-Allow-Origin: *'));
    expect(out).not.toContain('abcdef0123456789abcdef');
    expect(out).not.toContain('bob');
    expect(out).toContain('Access-Control-Allow-Origin: *');
  });
});

describe('Phase 9 error response redaction at the MCP boundary', () => {
  const hostile = 'Authorization: Digest username="bob", response="abcdef0123456789abcdef" Authorization: Basic dXNlcjpwYXNz Authorization: Token tok-abc123xyz';
  const secrets = ['abcdef0123456789abcdef', 'dXNlcjpwYXNz', 'tok-abc123xyz'];
  it.each([
    ['get_security_finding', { investigationId: hostile.slice(0, 120), findingId: hostile }],
    ['verify_remediation', { remediationId: hostile.slice(0, 120) }],
    ['rollback_remediation', { remediationId: hostile.slice(0, 120) }],
    ['get_investigation', { investigationId: hostile.slice(0, 120) }],
    ['scan_project', { [hostile.slice(0, 100)]: 1 }],
  ])('does not echo secrets from %s error responses', async (name, input) => {
    const tool = toolDefinitions.find((item) => item.name === name);
    expect(tool).toBeDefined();
    const response = await tool!.handler(securityConfig, input);
    expect(response.isError).toBe(true);
    const text = JSON.stringify(response);
    for (const secret of secrets) expect(text, `${name}:${secret}`).not.toContain(secret);
  });
});
