import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { detachedRedacted } from '../../src/report/redaction.js';
import type { AppConfig } from '../../src/config.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const config: AppConfig = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2 };

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

function payload(response: { content: Array<{ text: string }> }) {
  return JSON.parse(response.content[0]!.text) as any;
}

async function completedInvestigation() {
  const started = payload(await tool('start_security_investigation').handler(config, {
    projectPath: FIXTURE, scope: ['authentication', 'authorization'], hypothesis: 'Produce an evidence-backed report.',
  }));
  const investigationId = started.id as string;
  const analysis = payload(await tool('run_security_analysis').handler(config, { investigationId }));
  const findingId = analysis.analysis.accessControl.findingIds.find((id: string) => id.startsWith('CS-ACCESS-001'));
  await tool('record_security_hypothesis').handler(config, {
    investigationId,
    title: 'Missing authentication candidate',
    description: 'A sensitive administrative route lacks a visible authentication control.',
    findingId,
    evidenceRefs: [`accessFinding:${findingId}`],
    severity: 'high',
    confidence: 'medium',
  });
  await tool('request_runtime_verification').handler(config, {
    investigationId,
    hypothesisId: payload(await tool('get_investigation').handler(config, { investigationId })).hypotheses[0].id,
    findingId,
    target: { allowedOrigin: 'http://10.0.0.4:3000' },
  });
  return { investigationId, findingId };
}

beforeEach(() => resetInvestigationsForTests());

describe('Phase 8 report MCP surface', () => {
  it('registers report and finding tools and validates malformed input', async () => {
    expect(toolDefinitions.map((item) => item.name)).toEqual(expect.arrayContaining(['generate_security_report', 'get_security_finding']));
    const malformed = await tool('generate_security_report').handler(config, {});
    expect(malformed.isError).toBe(true);
    expect(payload(malformed).error).toBe('INVALID_INPUT');
    const unknown = await tool('generate_security_report').handler(config, { investigationId: 'missing' });
    expect(payload(unknown).error).toBe('INVESTIGATION_NOT_FOUND');
  });

  it('rejects incomplete investigations rather than presenting them as complete', async () => {
    const started = await tool('start_security_investigation').handler(config, { projectPath: FIXTURE, scope: ['authorization'], hypothesis: 'incomplete' });
    const response = await tool('generate_security_report').handler(config, { investigationId: payload(started).id });
    expect(payload(response).error).toBe('INVESTIGATION_INCOMPLETE');
  });
});

describe('Phase 8 evidence-backed report generation', () => {
  it('generates a blocked/static report with traceability and remediation', async () => {
    const before = crypto.createHash('sha256').update(fs.readFileSync(`${FIXTURE}/src/app.ts`)).digest('hex');
    const { investigationId, findingId } = await completedInvestigation();
    const response = await tool('generate_security_report').handler(config, { investigationId });
    expect(response.isError).toBe(false);
    const report = payload(response);
    expect(report.complete).toBe(true);
    expect(report.reportId).toBe(`report-${investigationId}`);
    expect(report.findings.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect(finding.evidenceRefs.length).toBeGreaterThan(0);
      expect(finding.sourceRefs.length).toBeGreaterThan(0);
      expect(finding.remediation.findingId).toBe(finding.findingId);
    }
    const targeted = report.findings.find((finding: { findingId: string }) => finding.findingId === findingId);
    expect(targeted.status).toBe('blocked');
    expect(targeted.remediation.reverifyAfterRemediation).toBe(true);
    expect(report.blockedVerificationCases).toContain(findingId);
    expect(report.unverifiedStaticFindings.length).toBeGreaterThan(0);
    const after = crypto.createHash('sha256').update(fs.readFileSync(`${FIXTURE}/src/app.ts`)).digest('hex');
    expect(after).toBe(before);
  });

  it('returns a finding-focused view with deterministic remediation', async () => {
    const { investigationId, findingId } = await completedInvestigation();
    const response = await tool('get_security_finding').handler(config, { investigationId, findingId });
    expect(response.isError).toBe(false);
    const finding = payload(response);
    expect(finding.findingId).toBe(findingId);
    expect(finding.evidenceRefs.length).toBeGreaterThan(0);
    expect(finding.remediation.recommendedChange).toContain('authentication');
    const unknown = await tool('get_security_finding').handler(config, { investigationId, findingId: 'missing' });
    expect(payload(unknown).error).toBe('REPORT_FINDING_NOT_FOUND');
  });

  it('is deterministic apart from generatedAt and sorts findings by technical severity/status/id', async () => {
    const { investigationId } = await completedInvestigation();
    const first = payload(await tool('generate_security_report').handler(config, { investigationId }));
    const second = payload(await tool('generate_security_report').handler(config, { investigationId }));
    const normalize = (report: any) => ({ ...report, generatedAt: '[dynamic]' });
    expect(normalize(first)).toEqual(normalize(second));
    const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const statusRank: Record<string, number> = { runtime_verified: 0, static_candidate: 1, inconclusive: 2, blocked: 3, not_reproduced: 4 };
    for (let index = 1; index < first.findings.length; index += 1) {
      const previous = `${severityRank[first.findings[index - 1].severity]}:${statusRank[first.findings[index - 1].status]}:${first.findings[index - 1].findingId}`;
      const current = `${severityRank[first.findings[index].severity]}:${statusRank[first.findings[index].status]}:${first.findings[index].findingId}`;
      expect(previous <= current).toBe(true);
    }
  });

  it('redacts nested credentials and bounds report values', () => {
    const value = detachedRedacted({ nested: { Authorization: 'Bearer super-secret', Cookie: 'session=secret' }, body: 'x'.repeat(10_000) }) as any;
    expect(JSON.stringify(value)).not.toContain('super-secret');
    expect(JSON.stringify(value)).not.toContain('session=secret');
    expect(value.body.length).toBeLessThanOrEqual(2_000);
  });
});

describe('Phase 8 report completeness and integrity', () => {
  it('carries bounded riskScore and synthesis on every finding without overclaiming runtime proof', async () => {
    const { investigationId, findingId } = await completedInvestigation();
    const report = payload(await tool('generate_security_report').handler(config, { investigationId }));
    expect(report.findings.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect(Number.isInteger(finding.riskScore)).toBe(true);
      expect(finding.riskScore).toBeGreaterThanOrEqual(0);
      expect(finding.riskScore).toBeLessThanOrEqual(100);
      expect(typeof finding.evidenceSynthesis).toBe('string');
      expect(finding.evidenceSynthesis.length).toBeLessThanOrEqual(600);
      expect(finding.remediationState).toEqual({ status: null, remediationIds: [] });
      if (finding.status !== 'runtime_verified') expect(finding.evidenceSynthesis).not.toContain('verified the condition');
      if (!finding.runtimeResult) expect(finding.evidenceSynthesis).not.toMatch(/Runtime proof/);
    }
    const single = payload(await tool('get_security_finding').handler(config, { investigationId, findingId }));
    const fromReport = report.findings.find((item: any) => item.findingId === findingId);
    expect(single.riskScore).toBe(fromReport.riskScore);
    expect(single.evidenceSynthesis).toBe(fromReport.evidenceSynthesis);
  });

  it('produces identical finding content for repeated reports', async () => {
    const { investigationId } = await completedInvestigation();
    const first = payload(await tool('generate_security_report').handler(config, { investigationId }));
    const second = payload(await tool('generate_security_report').handler(config, { investigationId }));
    expect(JSON.stringify(second.findings)).toBe(JSON.stringify(first.findings));
  });

  it('redacts the full credential set while keeping benign evidence readable', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop';
    const input = { notes: ['password=fixture-secret', 'key sk_live_abcdef1234567890', 'Authorization: Bearer abc.def.ghi', jwt, 'Authorization: Basic dXNlcjpwYXNzd29yZA==', 'postgres://admin:hunter2@db.local/app', 'Cookie: sid=abc123; theme=dark', 'Set-Cookie: session=zzz999; HttpOnly', '-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----', 'Access-Control-Allow-Origin: *'] };
    const out = JSON.stringify(detachedRedacted(input));
    for (const leak of ['fixture-secret', 'sk_live_abcdef', 'abc.def.ghi', 'eyJzdWIi', 'dXNlcjpw', 'hunter2', 'sid=abc123', 'session=zzz999', 'MIIabc']) expect(out).not.toContain(leak);
    expect(out).toContain('Access-Control-Allow-Origin: *');
  });

  it('redacts credentials in investigation views with the shared redactor', async () => {
    const started = payload(await tool('start_security_investigation').handler(config, { projectPath: FIXTURE, scope: ['authentication'], hypothesis: 'Check Authorization: Basic dXNlcjpwYXNzd29yZA== and key sk_live_abcdef1234567890 for exposure.' }));
    const view = JSON.stringify(payload(await tool('get_investigation').handler(config, { investigationId: started.id })));
    expect(view).not.toContain('dXNlcjpw');
    expect(view).not.toContain('sk_live_abcdef');
  });

  it('rejects forged lifecycle fields and malformed references safely', async () => {
    const forged: Array<[string, Record<string, unknown>]> = [
      ['generate_security_report', { investigationId: 'x', status: 'verified' }],
      ['get_security_finding', { investigationId: 'x', findingId: 'y', status: 'runtime_verified' }],
      ['verify_remediation', { remediationId: 'x', status: 'verified_resolved' }],
      ['rollback_remediation', { remediationId: 'x', verified: true }],
      ['verify_remediation', { remediationId: 'x'.repeat(200) }],
    ];
    for (const [name, input] of forged) {
      const response = await tool(name).handler(config, input);
      expect(response.isError).toBe(true);
      expect(payload(response).error).toBe('INVALID_INPUT');
    }
    for (const name of ['verify_remediation', 'apply_remediation', 'rollback_remediation']) {
      expect(payload(await tool(name).handler(config, { remediationId: 'missing' })).error).toBe('REMEDIATION_NOT_FOUND');
    }
    expect(payload(await tool('get_security_finding').handler(config, { investigationId: 'missing', findingId: 'f' })).error).toBe('INVESTIGATION_NOT_FOUND');
  });
});
