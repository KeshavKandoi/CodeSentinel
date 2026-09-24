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
