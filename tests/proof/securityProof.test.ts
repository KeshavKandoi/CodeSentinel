import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { analyzeAccessControl } from '../../src/access/engine.js';
import { discoverRoutes } from '../../src/routes/engine.js';
import { buildSecurityGraph, listSecurityProofAdapters, listSecurityProofCases, proveSecurityFinding } from '../../src/proof/engine.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';

const root = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };

beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });

describe('security proof engine', () => {
  it('uses an explicit adapter registry for executable proof classes', () => {
    const adapters = listSecurityProofAdapters();
    expect(adapters.map((adapter) => adapter.type)).toEqual(expect.arrayContaining(['idor_bola', 'missing_authentication', 'missing_authorization', 'authorization_inconsistency']));
    expect(adapters.some((adapter) => adapter.type === 'sql_injection')).toBe(false);
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
});
