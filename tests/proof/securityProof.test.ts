import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { analyzeAccessControl } from '../../src/access/engine.js';
import { discoverRoutes } from '../../src/routes/engine.js';
import { buildSecurityGraph, listSecurityProofAdapters, listSecurityProofCases, proveSecurityFinding } from '../../src/proof/engine.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';
import { scanProject } from '../../src/security/scanner.js';

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
    expect(adapters.some((adapter) => adapter.type === 'jwt_verification')).toBe(false);
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
});
