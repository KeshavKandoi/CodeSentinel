import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { scanProject } from '../../src/security/scanner.js';
import { listSecurityReceiptsForFinding, proveSecurityFinding, resetSecurityProofsForTests } from '../../src/proof/engine.js';
import { runSecurityAuditPipeline } from '../../src/audit/pipeline.js';
import { getInvestigation, runSecurityAnalysis, startInvestigation, resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';

const fixture = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const config = (projectRoot: string): AppConfig => ({ projectRoot, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 });

describe('proof receipt project isolation', () => {
  it('does not reuse a receipt for an identical finding in another project', async () => {
    resetSecurityProofsForTests();
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-proof-roots-'));
    const a = path.join(temp, 'a');
    const b = path.join(temp, 'b');
    fs.cpSync(fixture, a, { recursive: true });
    fs.cpSync(fixture, b, { recursive: true });
    try {
      const first = await scanProject(config(a));
      const second = await scanProject(config(b));
      expect(first.ok && second.ok).toBe(true);
      if (!first.ok || !second.ok) return;
      const findingId = first.data.findings[0]?.id;
      expect(findingId).toBeDefined();
      expect(second.data.findings.some((item) => item.id === findingId)).toBe(true);
      const target = { allowedOrigin: 'http://127.attacker.com:3000' };
      const proofA = await proveSecurityFinding(config(a), { findingId: findingId!, target });
      expect(proofA.ok).toBe(true);
      expect(listSecurityReceiptsForFinding(findingId!, b)).toHaveLength(0);
      const auditB = await runSecurityAuditPipeline(config(b), {});
      expect(auditB.ok).toBe(true);
      if (auditB.ok) expect(auditB.data.findings.every((item) => item.proof.receiptIds.length === 0)).toBe(true);
      const proofB = await proveSecurityFinding(config(b), { findingId: findingId!, target });
      expect(proofB.ok).toBe(true);
      if (proofA.ok && proofB.ok) expect(proofA.data.receiptId).not.toBe(proofB.data.receiptId);
      const otherOrigin = await proveSecurityFinding(config(a), { findingId: findingId!, target: { allowedOrigin: 'http://127.attacker.com:3001' } });
      expect(otherOrigin.ok).toBe(true);
      if (proofA.ok && otherOrigin.ok) expect(proofA.data.receiptId).not.toBe(otherOrigin.data.receiptId);
      expect(listSecurityReceiptsForFinding(findingId!, a)).toHaveLength(2);
      expect(listSecurityReceiptsForFinding(findingId!, b)).toHaveLength(1);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
      resetSecurityProofsForTests();
    }
  });
});

describe('investigation project isolation', () => {
  it('rejects another root before analysis and does not attach its state to an audit', async () => {
    resetInvestigationsForTests();
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-investigation-roots-'));
    const a = path.join(temp, 'a');
    const b = path.join(temp, 'b');
    fs.cpSync(fixture, a, { recursive: true });
    fs.cpSync(fixture, b, { recursive: true });
    try {
      const started = startInvestigation(config(a), { projectPath: a, scope: ['input_validation'], hypothesis: 'Inspect source.' });
      expect(started.ok).toBe(true);
      if (!started.ok) return;
      expect(getInvestigation(started.data.id, config(b))).toMatchObject({ ok: false, error: { code: 'PATH_OUTSIDE_ROOT' } });
      expect(await runSecurityAnalysis(config(b), started.data.id)).toMatchObject({ ok: false, error: { code: 'PATH_OUTSIDE_ROOT' } });
      const audit = await runSecurityAuditPipeline(config(b), { investigationId: started.data.id });
      expect(audit.ok).toBe(true);
      if (audit.ok) {
        expect(audit.data.remediation.records).toBe(0);
        expect(audit.data.issues.some((issue) => issue.code === 'INVESTIGATION_UNAVAILABLE')).toBe(true);
      }
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
      resetInvestigationsForTests();
    }
  });
});
