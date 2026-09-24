import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { toolDefinitions } from '../../src/tools/registry.js';
import { getInvestigation, resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const config: AppConfig = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
const PRIVATE_TARGET = { allowedOrigin: 'http://10.0.0.4:3000' };
const RESULT_STATUSES = ['verified', 'not_reproduced', 'inconclusive', 'blocked'];

let server: http.Server;
let origin = '';

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => { await new Promise<void>((resolve) => server.close(() => resolve())); });
beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}
async function call(name: string, args: unknown) {
  const response = await tool(name).handler(config, args);
  return { isError: response.isError, text: response.content[0]!.text, body: JSON.parse(response.content[0]!.text) as Record<string, any> };
}

async function analysedAudit(extra: Record<string, unknown> = {}) {
  const start = await call('start_security_audit', { objective: 'Review authorization of the admin API', focus: 'authorization', ...extra });
  const id = start.body.investigationId as string;
  await call('plan_security_investigation', { investigationId: id });
  const state = (await call('run_audit_analysis', { investigationId: id })).body;
  const candidates = (state.findings as any[]).filter((f) => f.origin === 'access_control');
  const finding = candidates.find((f) => f.candidateType === 'missing_authentication') ?? candidates[0];
  expect(finding, 'fixture must yield at least one access-control finding').toBeDefined();
  return { id, state, finding };
}

function hypothesis(id: string, hypothesisId: string, findingId?: string) {
  return { investigationId: id, hypothesisId, category: 'missing_authentication', description: `Route for ${hypothesisId} may be reachable without authentication`, affectedLocation: 'admin routes', reason: 'Static access-control analysis flagged this route', ...(findingId ? { findingId } : {}) };
}

describe('Phase 10 runtime verification through existing controls', () => {
  it('verifies via Phase 6 against a local target and links real evidence to the hypothesis', async () => {
    const { id, finding } = await analysedAudit();
    expect((await call('record_audit_hypothesis', hypothesis(id, 'h1', finding.findingId))).isError).toBe(false);
    const r = await call('request_audit_verification', { investigationId: id, hypothesisId: 'h1', findingId: finding.findingId, target: { allowedOrigin: origin } });
    expect(r.isError, r.text).toBe(false);
    expect(r.body.usage.verificationRequests).toBe(1);
    expect(r.body.verificationResults).toHaveLength(1);
    const v = r.body.verificationResults[0];
    expect(RESULT_STATUSES).toContain(v.status);
    expect(v.auditHypothesisId).toBe('h1');
    const h = r.body.hypotheses[0];
    expect(h.isEvidence).toBe(false);
    expect(h.investigationHypothesisId).toBeTruthy();
    expect(h.evidenceRefs).toContain(v.evidenceRef);
    const step = r.body.steps.find((s: any) => s.tool === 'request_audit_verification');
    expect(step.investigationStepIds.length).toBeGreaterThan(0);
    expect(r.body.findings.find((f: any) => f.findingId === finding.findingId).runtimeVerificationStatus).toBe(v.status);
    expect(r.text).not.toMatch(/authorization"?\s*:\s*"Bearer/i);
  });

  it('blocks a private-network target and records the blocked operation', async () => {
    const { id, finding } = await analysedAudit();
    await call('record_audit_hypothesis', hypothesis(id, 'h1', finding.findingId));
    await call('request_audit_verification', { investigationId: id, hypothesisId: 'h1', findingId: finding.findingId, target: PRIVATE_TARGET });
    const state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.usage.verificationRequests).toBe(1);
    expect(state.blockedOperations.length).toBeGreaterThan(0);
    expect(state.blockedOperations.some((b: any) => b.tool === 'request_audit_verification')).toBe(true);
    expect(state.hypotheses[0].isEvidence).toBe(false);
    expect(state.findings.every((f: any) => f.lifecycle !== 'runtime_verified')).toBe(true);
  });

  it('counts rejected attempts toward a hard limit (no unbounded retry loop)', async () => {
    const { id, finding } = await analysedAudit({ limits: { maxVerificationRequests: 2 } });
    await call('record_audit_hypothesis', hypothesis(id, 'h1', finding.findingId));
    const attempt = () => call('request_audit_verification', { investigationId: id, hypothesisId: 'h1', findingId: finding.findingId, target: PRIVATE_TARGET });
    await attempt();
    await attempt();
    const third = await attempt();
    expect(third.isError).toBe(true);
    expect(third.body.error).toBe('BUDGET_EXCEEDED');
    const state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.usage.verificationRequests).toBe(2);
  });

  it('cannot fabricate evidence or a verified status', async () => {
    for (const name of ['start_security_audit', 'record_audit_hypothesis', 'request_audit_verification', 'complete_security_audit']) {
      const props = Object.keys((tool(name).inputSchema as any).properties ?? {});
      for (const banned of ['evidence', 'evidenceRefs', 'status', 'verified', 'severity', 'result']) expect(props, `${name}.${banned}`).not.toContain(banned);
    }
    const injected = await call('record_audit_hypothesis', { ...hypothesis('x', 'h1'), evidenceRefs: ['fake'], status: 'verified' });
    expect(injected.body.error).toBe('INVALID_INPUT');
    const { id, finding } = await analysedAudit();
    expect((await call('record_audit_hypothesis', hypothesis(id, 'h-fake', 'not-a-real-finding'))).body.error).toBe('HYPOTHESIS_INVALID');
    expect((await call('request_audit_verification', { investigationId: id, hypothesisId: 'nope', findingId: finding.findingId, target: { allowedOrigin: origin } })).body.error).toBe('HYPOTHESIS_NOT_FOUND');
    await call('record_audit_hypothesis', hypothesis(id, 'h1', finding.findingId));
    expect((await call('request_audit_verification', { investigationId: id, hypothesisId: 'h1', findingId: 'other-finding', target: { allowedOrigin: origin } })).body.error).toBe('HYPOTHESIS_INVALID');
  });
});

describe('Phase 10 end-to-end (local synthetic fixture only)', () => {
  it('start -> plan -> analysis -> hypothesis -> verification -> complete -> report, fully traceable', async () => {
    const start = await call('start_security_audit', { objective: 'Review authorization of the admin API', focus: 'authorization' });
    const id = start.body.investigationId as string;
    expect(start.body.status).toBe('created');

    const plan = (await call('plan_security_investigation', { investigationId: id })).body;
    expect(plan.status).toBe('planning');
    expect(plan.capabilities.find((c: any) => c.tool === 'run_audit_analysis').status).toBe('available');

    const analysed = (await call('run_audit_analysis', { investigationId: id })).body;
    expect(analysed.status).toBe('awaiting_verification');
    const inv = getInvestigation(id);
    expect(inv.ok).toBe(true);
    if (!inv.ok) return;

    // The standalone read-only tools agree with what the audit executed.
    const routes = await call('discover_routes', {});
    const access = await call('analyze_access_control', {});
    expect(routes.body.entries.length).toBe(inv.data.analysis!.routes.total);
    expect(access.body.findings.length).toBe(inv.data.analysis!.accessControl.totalFindings);

    const candidates = (analysed.findings as any[]).filter((f) => f.origin === 'access_control');
    const finding = candidates.find((f) => f.candidateType === 'missing_authentication') ?? candidates[0];
    expect(finding).toBeDefined();

    const recorded = await call('record_audit_hypothesis', hypothesis(id, 'e2e-h1', finding.findingId));
    expect(recorded.body.isEvidence).toBe(false);

    const verified = await call('request_audit_verification', { investigationId: id, hypothesisId: 'e2e-h1', findingId: finding.findingId, target: { allowedOrigin: origin } });
    expect(verified.isError, verified.text).toBe(false);
    expect(verified.body.remainingWork.join(' ')).toContain('complete_security_audit');

    const done = (await call('complete_security_audit', { investigationId: id })).body;
    expect(done.status).toBe('completed');
    expect(done.complete).toBe(true);

    const detail = await call('get_security_finding', { investigationId: id, findingId: finding.findingId });
    expect(detail.isError, detail.text).toBe(false);
    expect(detail.body.findingId).toBe(finding.findingId);

    const report = await call('generate_security_audit_report', { investigationId: id });
    expect(report.isError, report.text).toBe(false);
    expect(report.body.report.investigationId).toBe(id);
    expect(report.body.report.findings.some((f: any) => f.findingId === finding.findingId)).toBe(true);

    const trace = report.body.traceability.find((t: any) => t.findingId === finding.findingId);
    expect(trace).toBeDefined();
    expect(trace.traceable).toBe(true);
    expect(trace.evidence.length).toBeGreaterThan(0);
    expect(trace.investigationStepIds.length).toBeGreaterThan(0);
    expect(trace.auditStepIds.length).toBeGreaterThan(0);
    const linkedHypothesis = done.hypotheses.find((h: any) => h.id === 'e2e-h1');
    expect(trace.auditHypothesisId).toBe('e2e-h1');
    expect(trace.investigationHypothesisId).toBe(linkedHypothesis.investigationHypothesisId);
    for (const t of report.body.traceability) if (t.evidence.length > 0) expect(t.auditStepIds.length).toBeGreaterThan(0);

    const after = (await call('plan_security_investigation', { investigationId: id })).body;
    expect(after.capabilities.find((c: any) => c.kind === 'controlled_remediation').status).toBe('available');
    const source = fs.readFileSync(`${FIXTURE}/${detail.body.affectedFile}`, 'utf8');
    const proposal = await call('propose_remediation', {
      investigationId: id,
      findingId: finding.findingId,
      description: 'Review the evidence-backed candidate.',
      rationale: 'The external agent proposes a controlled review; this handoff test makes no source change.',
      files: [{ path: detail.body.affectedFile, originalContentHash: crypto.createHash('sha256').update(source).digest('hex'), proposedContent: source, description: 'No-op orchestration handoff.' }],
      expectedSecurityEffect: 'No fix is claimed without Phase 9 verification.',
      requiresRuntimeVerification: false,
    });
    expect(proposal.isError, proposal.text).toBe(false);
    const finalReport = await call('generate_security_audit_report', { investigationId: id });
    expect(finalReport.isError, finalReport.text).toBe(false);
    expect(finalReport.body.report.remediations.some((r: any) => r.proposal.findingId === finding.findingId)).toBe(true);
  });
});
