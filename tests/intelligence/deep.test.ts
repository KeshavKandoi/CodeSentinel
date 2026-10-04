import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDeepSecurityAudit } from '../../src/intelligence/engine.js';
import { SECURITY_DOMAINS } from '../../src/intelligence/types.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';

const fixtureRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const cleanRoot = fs.realpathSync(fileURLToPath(new URL('../fixtures/generic-node', import.meta.url)));
const config = (projectRoot: string): AppConfig => ({ projectRoot, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 });

beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });

describe('deep security intelligence', () => {
  it('composes existing engines into bounded domain coverage with traceable evidence', async () => {
    const result = await runDeepSecurityAudit(config(fixtureRoot));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.domainCoverage).toHaveLength(SECURITY_DOMAINS.length);
    expect(result.data.repositoryIndex.files.length).toBeGreaterThan(0);
    expect(result.data.findings.length).toBeGreaterThan(0);
    expect(result.data.integrity.valid).toBe(true);
    const evidenceIds = new Set(result.data.evidence.map((item) => item.id));
    expect(result.data.findings.every((finding) => finding.evidenceIds.every((id) => evidenceIds.has(id)))).toBe(true);
    expect(result.data.markdown).toContain('Domain Coverage');
    expect(result.data.markdown).not.toContain('node-serialize');
  });

  it('does not treat a clean local fixture as a security guarantee and exposes bounded coverage', async () => {
    const result = await runDeepSecurityAudit(config(cleanRoot));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.integrity.valid).toBe(true);
    expect(result.data.coverage.filesAnalyzed).toBeGreaterThan(0);
    expect(result.data.limitations.some((item) => /runtime|external/i.test(item))).toBe(true);
  });

  it('honors the configured repository file bound', async () => {
    const result = await runDeepSecurityAudit(config(fixtureRoot), { maxFiles: 1 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.coverage.filesAnalyzed).toBeLessThanOrEqual(1);
    expect(result.data.coverage.filesSkipped).toBeGreaterThan(0);
  });

  it('compares stable finding IDs against a local baseline without external access', async () => {
    const baselinePath = path.join(fixtureRoot, 'deep-baseline.json');
    fs.writeFileSync(baselinePath, JSON.stringify({ findings: [{ id: 'old-finding', evidenceIds: ['old-evidence'] }] }));
    try {
      const result = await runDeepSecurityAudit(config(fixtureRoot), { baselinePath: 'deep-baseline.json' });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.data.baseline.supplied).toBe(true);
      expect(result.data.baseline.resolvedFindings).toContain('old-finding');
    } finally {
      fs.rmSync(baselinePath, { force: true });
    }
  });

  it('is exposed as one bounded MCP capability', async () => {
    const tool = toolDefinitions.find((item) => item.name === 'run_deep_security_audit');
    expect(tool).toBeDefined();
    const response = await tool!.handler(config(cleanRoot), { baselinePath: '../../outside.json' });
    expect(response.isError).toBe(true);
    expect(response.content[0]!.text).toContain('PATH_OUTSIDE_ROOT');
  });
});

async function phase5Project(files: Record<string, string>): Promise<string> {
  const os = await import('node:os');
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-p5-')));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

describe('Phase 5 deep analysis precision, redaction and merging', () => {
  it('ignores comments, documentation and untainted sinks but still reports a tainted command sink', async () => {
    const root = await phase5Project({
      'package.json': JSON.stringify({ name: 't', dependencies: { express: '^4.19.2' } }),
      'src/app.js': [
        "const cp = require('child_process');",
        "const express = require('express');",
        'const app = express();',
        "app.get('/health', (req, res) => res.send('ok'));",
        'const page = req.query.page;',
        "// app.post('/x', (req, res) => exec(req.body.cmd));",
        "app.post('/run', (req, res) => exec(req.body.cmd));",
        'const port = process.env.PORT;',
        '',
      ].join('\n'),
      'README.md': "app.get('/docs', (req, res) => res.send(req.query.x))\n",
    });
    try {
      const result = await runDeepSecurityAudit(config(root));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const located = result.data.findings.map((finding) => {
        const evidence = result.data.evidence.find((item) => item.id === finding.evidenceIds[0]);
        return { domain: finding.domain, file: evidence?.file, line: evidence?.line };
      });
      expect(located.some((item) => item.file === 'README.md')).toBe(false);
      expect(located.filter((item) => item.domain === 'command_execution')).toEqual([{ domain: 'command_execution', file: 'src/app.js', line: 7 }]);
      expect(located.some((item) => ['injection', 'xss', 'environment_configuration'].includes(item.domain))).toBe(false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('redacts credentials on scanned source lines and still completes the audit', async () => {
    const root = await phase5Project({
      'package.json': JSON.stringify({ name: 't', dependencies: { express: '^4.19.2' } }),
      'src/a.js': [
        "const h = 'Authorization: Bearer abcdefghij12345'; // jwt verify",
        "const u = 'postgres://admin:hunter2pw@db.internal/app'; // process.env fallback",
        "const t = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJl'; // jwt verify",
        '',
      ].join('\n'),
    });
    try {
      const result = await runDeepSecurityAudit(config(root));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const text = JSON.stringify(result.data);
      for (const secret of ['abcdefghij12345', 'hunter2pw', 'eyJhbGci']) expect(text).not.toContain(secret);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('does not let a heuristic deep finding raise severity or replace the title of a scanner finding', async () => {
    const { createFinding, addOrMerge } = await import('../../src/audit/identity.js');
    const base = { id: 'cs-merge', category: 'authentication', file: 'src/a.ts', line: 3, route: null, routeId: null, evidence: ['e'], recommendation: 'r' };
    const scan = () => createFinding({ ...base, title: 'Scanner title', severity: 'medium', confidence: 'medium', sources: [{ stage: 'static_scan', origin: 'security_scan', sourceId: 's1', ruleId: 'CS-NODE-008', category: 'authentication', candidateType: null, routePath: null }] });
    const deep = () => createFinding({ ...base, title: 'Deep title', severity: 'high', confidence: 'high', sources: [{ stage: 'deep_analysis', origin: 'deep_analysis', sourceId: 'd1', ruleId: null, category: 'jwt', candidateType: null, routePath: null }] });
    const scanFirst = new Map();
    addOrMerge(scanFirst, scan());
    addOrMerge(scanFirst, deep());
    const a = scanFirst.get('cs-merge');
    expect([a.severity, a.title, a.confidence, a.sources.length]).toEqual(['medium', 'Scanner title', 'medium', 2]);
    const deepFirst = new Map();
    addOrMerge(deepFirst, deep());
    addOrMerge(deepFirst, scan());
    const b = deepFirst.get('cs-merge');
    expect([b.severity, b.title, b.confidence, b.sources.length]).toEqual(['medium', 'Scanner title', 'medium', 2]);
  });
});

describe('Phase 5 proof eligibility requires a containing route for scan findings', () => {
  it('blocks a runtime-capable scan finding outside any route and keeps one inside a route eligible', async () => {
    const { createFinding } = await import('../../src/audit/identity.js');
    const { classifyFinding } = await import('../../src/audit/classify.js');
    const make = (line: number) => createFinding({
      id: `cs-route-${line}`, category: 'cors', title: 'Insecure CORS configuration', severity: 'medium', confidence: 'high',
      file: 'src/app.ts', line, route: null, routeId: null, evidence: ['e'], recommendation: 'r',
      sources: [{ stage: 'static_scan', origin: 'security_scan', sourceId: `s${line}`, ruleId: 'CS-NODE-007', category: 'cors', candidateType: null, routePath: null }],
    });
    const routes = [{ file: 'src/app.ts', sourceRange: { startLine: 10, endLine: 14 } }] as never;
    expect(classifyFinding(make(12), routes).proofStatus).toBe('eligible');
    expect(classifyFinding(make(30), routes).proofStatus).toBe('blocked');
    expect(classifyFinding(make(30)).proofStatus).toBe('eligible');
  });
});
