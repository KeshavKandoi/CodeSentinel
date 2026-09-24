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

const root = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const securityRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
const securityConfig: AppConfig = { ...config, projectRoot: securityRoot };
let proofServer: http.Server;
let proofOrigin = '';

beforeAll(async () => {
  proofServer = http.createServer((request, response) => {
    if (new URL(request.url ?? '/', 'http://127.0.0.1').pathname === '/search') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ proof: 'CODESENTINEL_PROOF_SQLI_SENTINEL' }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise<void>((resolve) => proofServer.listen(0, '127.0.0.1', resolve));
  const address = proofServer.address();
  if (!address || typeof address === 'string') throw new Error('Proof fixture did not expose a TCP address.');
  proofOrigin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => proofServer.close((error) => error ? reject(error) : resolve()));
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
    const { scanProject } = await import('../../src/security/scanner.js');
    const scan = await scanProject(securityConfig);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    const finding = scan.data.findings.find((item) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;

    const result = await proveSecurityFinding(securityConfig, { findingId: finding.id, target: { allowedOrigin: proofOrigin } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.status).toBe('verified');
    expect(result.data.oracle).toBe('verified');
    expect(result.data.responseFacts[0]?.bodySnippet).toContain('CODESENTINEL_PROOF_SQLI_SENTINEL');
    expect(JSON.stringify(result.data)).not.toContain('Authorization');
    expect(result.data.sourceRefs.length).toBeGreaterThan(0);
    expect(result.data.evidenceRefs).toEqual(expect.arrayContaining([`static:${finding.id}`]));
  });
});
