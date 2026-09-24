import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { discoverRoutes } from '../../src/routes/engine.js';
import { analyzeAccessControl } from '../../src/access/engine.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import type { AppConfig } from '../../src/config.js';
import type { AccessControlEntry, AnalyzeAccessControlResult } from '../../src/access/types.js';

const EXPRESS_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const EXPRESS_ROUTES_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/express-routes', import.meta.url)));
const FASTAPI_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/fastapi-routes', import.meta.url)));

function cfg(root: string): AppConfig {
  return { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
}

function analyze(root: string): AnalyzeAccessControlResult {
  const routes = discoverRoutes(cfg(root));
  if (!routes.ok) throw new Error(`discoverRoutes failed: ${routes.error.message}`);
  return analyzeAccessControl(cfg(root), routes.data.entries);
}

function entryFor(result: AnalyzeAccessControlResult, method: string, path: string): AccessControlEntry {
  const e = result.matrix.find((x) => x.method === method && x.path === path);
  if (!e) throw new Error(`no matrix entry for ${method} ${path}`);
  return e;
}

describe('Phase 5 access-control engine: Express fixture', () => {
  const result = analyze(EXPRESS_FIXTURE);

  it('analyzes every discovered route and produces route IDs matching AttackSurfaceEntry ids', () => {
    const routes = discoverRoutes(cfg(EXPRESS_FIXTURE));
    if (!routes.ok) throw new Error('discoverRoutes failed');
    expect(result.matrix.length).toBe(routes.data.entries.length);
    const routeIds = new Set(routes.data.entries.map((e) => e.id));
    for (const entry of result.matrix) {
      expect(routeIds.has(entry.routeId)).toBe(true);
    }
  });

  it('classifies a route with no guard as public', () => {
    const e = entryFor(result, 'GET', '/public/ping');
    expect(e.state).toBe('public');
    expect(e.authentication).toEqual([]);
  });

  it('classifies an authenticated read with no ownership check as authenticated', () => {
    const e = entryFor(result, 'GET', '/documents/:id');
    expect(e.state).toBe('authenticated');
    expect(e.authentication.length).toBeGreaterThan(0);
    expect(e.ownership).toEqual([]);
    expect(e.resourceParameters).toContain('id');
    expect(e.resourceLoads.some((l) => l.operation === 'read')).toBe(true);
  });

  it('classifies an authenticated write with an explicit ownership comparison as ownership_protected', () => {
    const e = entryFor(result, 'PUT', '/documents/:id');
    expect(e.state).toBe('ownership_protected');
    expect(e.ownership.length).toBeGreaterThan(0);
    expect(e.ownership[0]?.identity).toBe('req.user');
  });

  it('classifies an authenticated delete with no ownership check as authenticated (IDOR candidate)', () => {
    const e = entryFor(result, 'DELETE', '/documents/:id');
    expect(e.state).toBe('authenticated');
    expect(e.ownership).toEqual([]);
    expect(e.resourceLoads.some((l) => l.operation === 'delete')).toBe(true);
  });

  it('classifies a route with a real role guard as role_protected and marks it administrative', () => {
    const e = entryFor(result, 'GET', '/admin/reports');
    expect(e.state).toBe('role_protected');
    expect(e.administrative).toBe(true);
    expect(e.authorization.some((a) => a.kind === 'role')).toBe(true);
  });

  it('classifies an unguarded administrative route as public and flags it as administrative', () => {
    const e = entryFor(result, 'POST', '/admin/reset');
    expect(e.state).toBe('public');
    expect(e.administrative).toBe(true);
    expect(e.stateChanging).toBe(true);
  });

  it('produces an idor_candidate finding for the unprotected delete-by-id route', () => {
    const f = result.findings.find((x) => x.candidateType === 'idor_candidate');
    expect(f).toBeDefined();
    expect(f?.method).toBe('DELETE');
    expect(f?.path).toBe('/documents/:id');
    expect(f?.status).toBe('suspected');
    expect(f?.verificationStatus).toBe('not_verified');
    expect(f?.routeId).toBe(entryFor(result, 'DELETE', '/documents/:id').routeId);
  });

  it('produces a user_resource_access finding for the unprotected read-by-id route', () => {
    const f = result.findings.find((x) => x.candidateType === 'user_resource_access');
    expect(f).toBeDefined();
    expect(f?.method).toBe('GET');
    expect(f?.path).toBe('/documents/:id');
  });

  it('produces a missing_authentication finding for the unguarded admin route', () => {
    const f = result.findings.find((x) => x.candidateType === 'missing_authentication');
    expect(f).toBeDefined();
    expect(f?.method).toBe('POST');
    expect(f?.path).toBe('/admin/reset');
  });

  it('does not flag the ownership-protected route with any finding', () => {
    const put = result.findings.filter((x) => x.method === 'PUT' && x.path === '/documents/:id');
    expect(put).toEqual([]);
  });

  it('every finding has evidence pointing at a real source location inside the fixture', () => {
    for (const f of result.findings) {
      expect(f.file).toBeDefined();
      for (const ev of f.evidence) {
        expect(ev.file).toBeDefined();
        expect(fs.existsSync(`${EXPRESS_FIXTURE}/${ev.file}`)).toBe(true);
      }
    }
  });

  it('does not crash on the malformed file in the fixture and never produces a matrix entry from it', () => {
    expect(result.matrix.some((e) => e.file.includes('broken'))).toBe(false);
    expect(Array.isArray(result.warnings)).toBe(true);
  });
});

describe('Phase 5 access-control engine: false-positive resistance', () => {
  const result = analyze(EXPRESS_FIXTURE);

  it('does not treat comment text or unrelated string literals mentioning admin/role/token as guards', () => {
    const e = entryFor(result, 'GET', '/public/ping');
    expect(e.state).toBe('public');
    expect(e.authentication).toEqual([]);
    expect(e.authorization).toEqual([]);
  });

  it('does not classify every /documents/:id method identically merely because "id" and "documents" appear nearby', () => {
    const get = entryFor(result, 'GET', '/documents/:id');
    const put = entryFor(result, 'PUT', '/documents/:id');
    const del = entryFor(result, 'DELETE', '/documents/:id');
    expect(new Set([get.state, put.state, del.state]).size).toBeGreaterThan(1);
  });
});

describe('Phase 5 access-control engine: regression against the existing Express routes fixture', () => {
  const result = analyze(EXPRESS_ROUTES_FIXTURE);

  it('flags GET /users/:id as inconsistent with the role-protected DELETE on the same resource', () => {
    const f = result.findings.find((x) => x.candidateType === 'inconsistent_authorization');
    expect(f).toBeDefined();
    expect(f?.method).toBe('GET');
    expect(f?.path).toBe('/users/:id');
  });

  it('classifies the inherited-middleware admin route as protected', () => {
    const e = entryFor(result, 'GET', '/admin/stats');
    expect(['role_protected', 'permission_protected', 'authenticated']).toContain(e.state);
  });
});

describe('Phase 5 access-control engine: Python/FastAPI fixture (smoke test)', () => {
  it('runs against a Python framework without crashing and returns a valid result shape', () => {
    const result = analyze(FASTAPI_FIXTURE);
    expect(result.project.ecosystem).toBe('python');
    expect(Array.isArray(result.matrix)).toBe(true);
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.warnings)).toBe(true);
    const validStates = ['public', 'authenticated', 'role_protected', 'permission_protected', 'ownership_protected', 'mixed', 'unknown'];
    for (const entry of result.matrix) {
      expect(validStates).toContain(entry.state);
    }
    for (const finding of result.findings) {
      expect(finding.status).toBe('suspected');
      expect(finding.verificationStatus).toBe('not_verified');
    }
  });
});

describe('analyze_access_control MCP tool', () => {
  const tool = toolDefinitions.find((t) => t.name === 'analyze_access_control');

  it('is registered and returns the structured AnalyzeAccessControlResult', async () => {
    if (!tool) throw new Error('analyze_access_control tool not registered');
    const res = await tool.handler(cfg(EXPRESS_FIXTURE), {});
    expect(res.isError).toBe(false);
    const parsed = JSON.parse(res.content[0]!.text);
    expect(parsed.project).toBeDefined();
    expect(Array.isArray(parsed.matrix)).toBe(true);
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(Array.isArray(parsed.warnings)).toBe(true);
    expect(parsed.summary.totalRoutes).toBe(parsed.matrix.length);
  });

  it('rejects unknown input keys', async () => {
    if (!tool) throw new Error('analyze_access_control tool not registered');
    const res = await tool.handler(cfg(EXPRESS_FIXTURE), { extra: 1 });
    expect(res.isError).toBe(true);
    expect(JSON.parse(res.content[0]!.text).error).toBe('INVALID_INPUT');
  });

  it('chains cleanly from discover_routes entries (same route count end-to-end)', async () => {
    const discoverTool = toolDefinitions.find((t) => t.name === 'discover_routes');
    const accessTool = toolDefinitions.find((t) => t.name === 'analyze_access_control');
    if (!discoverTool || !accessTool) throw new Error('required tools not registered');
    const routesRes = await discoverTool.handler(cfg(EXPRESS_FIXTURE), {});
    const accessRes = await accessTool.handler(cfg(EXPRESS_FIXTURE), {});
    const routesParsed = JSON.parse(routesRes.content[0]!.text);
    const accessParsed = JSON.parse(accessRes.content[0]!.text);
    expect(accessParsed.matrix.length).toBe(routesParsed.entries.length);
  });
});
