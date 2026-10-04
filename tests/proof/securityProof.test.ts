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
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.status).toBe('blocked');
    expect(result.data.whyProven).toBe('');
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
    expect(missing.ok).toBe(true);
    if (missing.ok) expect(missing.data.status).toBe('blocked');
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
    let rejected = 0;
    for (let i = 0; i < 12; i++) {
      const result = await proveSecurityFinding(vulnerableProofConfig, { findingId: 'budget-probe', target: { allowedOrigin: vulnerableProofOrigin } });
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
