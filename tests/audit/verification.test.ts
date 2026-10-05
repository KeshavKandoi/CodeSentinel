import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { createFinding } from '../../src/audit/identity.js';
import { assessVerification } from '../../src/audit/verification.js';
import { runSecurityAuditPipeline } from '../../src/audit/pipeline.js';

const root = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 };

function finding(ruleId = 'CS-NODE-022') {
  return createFinding({
    id: 'cs-test', category: 'authentication', title: 'Identity', severity: 'high', confidence: 'medium',
    file: 'src/server.ts', line: 12, route: null, routeId: null,
    sources: [{ stage: 'static_scan', origin: 'security_scan', sourceId: 'scan-1', ruleId, category: 'authentication', candidateType: null, routePath: null }],
    evidence: ['Parsed message identity reaches registerUser'], recommendation: 'Authenticate first.',
  });
}

describe('Phase 4 verification assessment', () => {
  it('keeps source evidence unverified without an adapter and explains limits', () => {
    const item = finding();
    item.status = 'unsupported';
    item.classification.reason = 'No executable proof adapter exists.';
    const assessment = assessVerification(item);
    expect(assessment).toMatchObject({ findingId: 'cs-test', ruleIds: ['CS-NODE-022'], originalSeverity: 'high', confidence: 'medium', verificationStatus: 'not_verifiable', proofStatus: 'unsupported', proofMethod: 'static_source_to_sink_trace', receiptIds: [] });
    expect(assessment.evidence).toContain('Parsed message identity reaches registerUser');
    expect(assessment.limitations.join(' ')).toContain('authentication helpers');
  });

  it('reports registered proof eligibility, safe failure, and negative outcomes separately', () => {
    const item = finding('CS-NODE-016');
    item.status = 'proof_eligible';
    item.classification = { proofSupport: 'runtime', proofStatus: 'eligible', adapter: 'jwt_verification', proofSourceId: 'scan-1', prerequisites: [], maxRequests: 2, reason: 'Authorized target required.' };
    expect(assessVerification(item).verificationStatus).toBe('not_verified');
    item.status = 'blocked'; item.proof.attempted = true; item.proof.status = 'blocked'; item.proof.note = 'Local target refused the request.';
    expect(assessVerification(item)).toMatchObject({ verificationStatus: 'verification_failed', proofMethod: 'registered:jwt_verification' });
    item.status = 'not_reproduced'; item.proof.status = 'not_reproduced';
    expect(assessVerification(item).verificationStatus).toBe('not_verified');
    item.status = 'verified'; item.proof.status = 'verified'; item.proof.receiptIds = ['receipt-1'];
    expect(assessVerification(item)).toMatchObject({ verificationStatus: 'verified', receiptIds: ['receipt-1'] });
  });

  it('emits bounded assessments without changing the source tree', async () => {
    const audit = await runSecurityAuditPipeline(config, {});
    expect(audit.ok).toBe(true);
    if (!audit.ok) return;
    expect(audit.data.readOnly.sourceTreeUnchanged).toBe(true);
    for (const item of audit.data.findings) {
      expect(item.verification?.findingId).toBe(item.id);
      expect(item.verification?.evidence.length).toBeLessThanOrEqual(5);
      expect(item.verification?.safetyConstraints.length).toBeGreaterThan(0);
      expect(item.verification?.verificationStatus).not.toBe('verified');
    }
  });
});
