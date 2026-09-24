import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { toolDefinitions } from '../../src/tools/registry.js';
import { getInvestigation, resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { canTransition, getSecurityAuditState, requestAuditVerification, resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import { AUDIT_STATUSES } from '../../src/orchestration/types.js';
import type { AppConfig } from '../../src/config.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const EMPTY_FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/generic-node', import.meta.url)));
const config: AppConfig = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
const emptyConfig: AppConfig = { ...config, projectRoot: EMPTY_FIXTURE };

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

async function call(name: string, args: unknown, cfg: AppConfig = config) {
  const response = await tool(name).handler(cfg, args);
  const text = response.content[0]!.text;
  return { isError: response.isError, text, body: JSON.parse(text) as Record<string, any> };
}

async function newAudit(cfg: AppConfig = config, extra: Record<string, unknown> = {}): Promise<string> {
  const r = await call('start_security_audit', { objective: 'Review authentication and authorization of the API', ...extra }, cfg);
  expect(r.isError).toBe(false);
  return r.body.investigationId as string;
}

async function readyAudit(cfg: AppConfig = config, extra: Record<string, unknown> = {}): Promise<string> {
  const id = await newAudit(cfg, extra);
  expect((await call('plan_security_investigation', { investigationId: id }, cfg)).isError).toBe(false);
  return id;
}

function hypothesis(id: string, hypothesisId: string, extra: Record<string, unknown> = {}) {
  return { investigationId: id, hypothesisId, category: 'missing_authentication', description: `Route ${hypothesisId} may lack authentication`, affectedLocation: `src/app.ts:${hypothesisId}`, reason: 'Observed no auth middleware in the discovered route inventory', ...extra };
}

beforeEach(() => {
  resetInvestigationsForTests();
  resetAuditSessionsForTests();
});

describe('Phase 10 registration and input validation', () => {
  it('registers the orchestration tools and keeps the existing tools', () => {
    const names = toolDefinitions.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining([
      'start_security_audit', 'plan_security_investigation', 'get_security_audit_state', 'run_audit_analysis',
      'record_audit_hypothesis', 'request_audit_verification', 'complete_security_audit', 'generate_security_audit_report',
      'start_security_investigation', 'record_security_hypothesis', 'generate_security_report', 'propose_remediation', 'run_command',
    ]));
    expect(new Set(names).size).toBe(names.length);
  });

  it('starts an audit without treating the objective as a finding', async () => {
    const r = await call('start_security_audit', { objective: 'Review authentication and authorization of the API' });
    expect(r.isError).toBe(false);
    expect(r.body.status).toBe('created');
    expect(r.body.objective.focus).toBe('authentication');
    expect(r.body.objective.notice).toContain('not a finding');
    expect(r.body.findings).toEqual([]);
    expect(r.body.evidenceRefs.total).toBe(0);
    expect(r.body.complete).toBe(false);
  });

  it('accepts an explicit focus and a route target', async () => {
    const r = await call('start_security_audit', { objective: 'Look at one route', focus: 'route', target: 'GET /admin/users' });
    expect(r.isError).toBe(false);
    expect(r.body.objective.focus).toBe('route');
    expect(r.body.objective.target).toBe('GET /admin/users');
  });

  it('rejects malformed, empty, oversized, and inconsistent input', async () => {
    const bad: unknown[] = [
      {}, { objective: '' }, { objective: '   ' }, { objective: 'x'.repeat(1001) }, { objective: 'ok', extra: true },
      { objective: 'ok', focus: 'route' }, { objective: 'ok', target: '/x' }, { objective: 'ok', focus: 'nonsense' },
      { objective: 'ok', limits: { maxSteps: 0 } }, { objective: 'ok', limits: { maxOutputBytes: 100 } }, { objective: 'ok', limits: { unknown: 1 } },
    ];
    for (const input of bad) {
      const r = await call('start_security_audit', input);
      expect(r.isError).toBe(true);
      expect(r.body.error).toBe('INVALID_INPUT');
    }
  });

  it('returns INVESTIGATION_NOT_FOUND for unknown IDs on every id-based tool', async () => {
    for (const name of ['plan_security_investigation', 'get_security_audit_state', 'run_audit_analysis', 'complete_security_audit', 'generate_security_audit_report']) {
      const r = await call(name, { investigationId: 'missing' });
      expect(r.isError).toBe(true);
      expect(r.body.error).toBe('INVESTIGATION_NOT_FOUND');
    }
    const h = await call('record_audit_hypothesis', hypothesis('missing', 'h1'));
    expect(h.body.error).toBe('INVESTIGATION_NOT_FOUND');
  });
});

describe('Phase 10 deterministic planning', () => {
  it('produces identical plans for identical objectives and differs by focus', async () => {
    const a = await readyAudit();
    const b = await readyAudit();
    const planA = (await call('plan_security_investigation', { investigationId: a })).body;
    const planB = (await call('plan_security_investigation', { investigationId: b })).body;
    expect(planA.capabilities).toEqual(planB.capabilities);
    expect(planA.objective.scopes).toEqual(planB.objective.scopes);
    expect(planA.relevantFindingCategories).toEqual(planB.relevantFindingCategories);
    expect(planA.notice).toContain('not a security conclusion');
    const secrets = await newAudit(config, { objective: 'Check for hardcoded secrets', focus: 'secrets' });
    const planC = (await call('plan_security_investigation', { investigationId: secrets })).body;
    expect(planC.relevantFindingCategories).toEqual(['secrets']);
    expect(planC.relevantFindingCategories).not.toEqual(planA.relevantFindingCategories);
  });

  it('moves created to planning and lists analysis as available', async () => {
    const id = await newAudit();
    const plan = (await call('plan_security_investigation', { investigationId: id })).body;
    expect(plan.status).toBe('planning');
    const analysis = plan.capabilities.find((c: any) => c.tool === 'run_audit_analysis');
    expect(analysis.status).toBe('available');
    expect(plan.capabilities.find((c: any) => c.kind === 'controlled_remediation').status).toBe('unavailable');
  });
});

describe('Phase 10 lifecycle', () => {
  it('allows exactly the documented transitions', () => {
    const expected: Record<string, string[]> = {
      created: ['planning', 'blocked', 'failed'], planning: ['investigating', 'blocked', 'failed'],
      investigating: ['awaiting_verification', 'completed', 'blocked', 'failed'], awaiting_verification: ['completed', 'blocked', 'failed'],
      completed: [], blocked: [], failed: [],
    };
    for (const from of AUDIT_STATUSES) for (const to of AUDIT_STATUSES) {
      expect(canTransition(from, to), `${from} -> ${to}`).toBe(expected[from]!.includes(to));
    }
  });

  it('rejects out-of-order operations with the right error', async () => {
    const id = await newAudit();
    expect((await call('run_audit_analysis', { investigationId: id })).body.error).toBe('INVALID_TRANSITION');
    expect((await call('record_audit_hypothesis', hypothesis(id, 'h1'))).body.error).toBe('INVALID_TRANSITION');
    expect((await call('complete_security_audit', { investigationId: id })).body.error).toBe('INVESTIGATION_INCOMPLETE');
    expect((await call('generate_security_audit_report', { investigationId: id })).body.error).toBe('INVESTIGATION_INCOMPLETE');
    await call('plan_security_investigation', { investigationId: id });
    const verify = await requestAuditVerification(config, { investigationId: id, hypothesisId: 'h', findingId: 'f', target: { allowedOrigin: 'http://127.0.0.1:1' } } as never);
    expect(verify.ok).toBe(false);
    if (!verify.ok) expect(verify.error.code).toBe('INVALID_TRANSITION');
  });
});

describe('Phase 10 hypotheses', () => {
  it('records a hypothesis before analysis and keeps it separate from evidence', async () => {
    const id = await readyAudit();
    const r = await call('record_audit_hypothesis', hypothesis(id, 'h1'));
    expect(r.isError).toBe(false);
    expect(r.body.kind).toBe('hypothesis');
    expect(r.body.isEvidence).toBe(false);
    expect(r.body.status).toBe('proposed');
    let state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.hypotheses).toHaveLength(1);
    expect(state.evidenceRefs.total).toBe(0);
    expect(state.findings).toEqual([]);
    await call('run_audit_analysis', { investigationId: id });
    state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.evidenceRefs.listed.some((e: any) => e.id === 'h1' || e.reference.includes('h1') || e.kind === 'hypothesis')).toBe(false);
    expect(state.findings.every((f: any) => f.lifecycle !== 'runtime_verified')).toBe(true);
    expect(state.hypotheses[0].status).toBe('proposed');
  });

  it('rejects duplicate hypothesis ids and duplicate content', async () => {
    const id = await readyAudit();
    await call('record_audit_hypothesis', hypothesis(id, 'h1'));
    expect((await call('record_audit_hypothesis', hypothesis(id, 'h1', { description: 'other', affectedLocation: 'other' }))).body.error).toBe('DUPLICATE_OPERATION');
    expect((await call('record_audit_hypothesis', { ...hypothesis(id, 'h2'), description: hypothesis(id, 'h1').description, affectedLocation: hypothesis(id, 'h1').affectedLocation }))).toMatchObject({ isError: true });
  });

  it('rejects malformed hypotheses', async () => {
    const id = await readyAudit();
    for (const bad of [
      hypothesis(id, 'bad id!'), { ...hypothesis(id, 'h1'), reason: '' }, { ...hypothesis(id, 'h1'), description: 'x'.repeat(4001) },
      { ...hypothesis(id, 'h1'), extra: 1 }, { ...hypothesis(id, 'h1'), category: '<script>' },
    ]) {
      const r = await call('record_audit_hypothesis', bad);
      expect(r.body.error).toBe('INVALID_INPUT');
    }
  });

  it('enforces the maximum number of hypotheses without ending the audit', async () => {
    const id = await readyAudit(config, { limits: { maxHypotheses: 1 } });
    expect((await call('record_audit_hypothesis', hypothesis(id, 'h1'))).isError).toBe(false);
    const second = await call('record_audit_hypothesis', hypothesis(id, 'h2', { description: 'different', affectedLocation: 'elsewhere' }));
    expect(second.body.error).toBe('BUDGET_EXCEEDED');
    const state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.status).toBe('planning');
    expect(state.blockedOperations.some((b: any) => b.code === 'BUDGET_EXCEEDED')).toBe(true);
  });
});

describe('Phase 10 analysis, bounds and traceability', () => {
  it('links the audit step to real investigation steps and evidence', async () => {
    const id = await readyAudit();
    const run = await call('run_audit_analysis', { investigationId: id });
    expect(run.isError).toBe(false);
    const inv = getInvestigation(id);
    expect(inv.ok).toBe(true);
    if (!inv.ok) return;
    const step = run.body.steps.find((s: any) => s.tool === 'run_audit_analysis');
    expect(step.investigationStepIds).toEqual(inv.data.steps.map((s) => s.id));
    expect(step.evidenceCount).toBe(inv.data.evidence.length);
    expect(run.body.totals.evidenceRefs).toBe(inv.data.evidence.length);
    expect(['awaiting_verification', 'investigating']).toContain(run.body.status);
    expect((await call('run_audit_analysis', { investigationId: id })).body.steps).toHaveLength(run.body.steps.length);
  });

  it('bounds listed evidence references', async () => {
    const id = await readyAudit(config, { limits: { maxEvidenceRefs: 1 } });
    const state = (await call('run_audit_analysis', { investigationId: id })).body;
    expect(state.evidenceRefs.listed.length).toBeLessThanOrEqual(1);
    expect(state.evidenceRefs.total).toBeGreaterThan(1);
    expect(state.evidenceRefs.truncated).toBe(true);
  });

  it('keeps the serialized state within the output limit', async () => {
    const id = await readyAudit(config, { limits: { maxOutputBytes: 8000 } });
    const r = await call('run_audit_analysis', { investigationId: id });
    expect(Buffer.byteLength(r.text, 'utf8')).toBeLessThanOrEqual(8000);
    if (r.body.totals.evidenceRefs > 10) expect(r.body.outputTruncated).toBe(true);
  });

  it('blocks the audit when the step limit is reached and records the blocked operation', async () => {
    const id = await readyAudit(config, { limits: { maxSteps: 2 } });
    await call('run_audit_analysis', { investigationId: id });
    const refused = await call('record_audit_hypothesis', hypothesis(id, 'h1'));
    expect(refused.body.error).toBe('BUDGET_EXCEEDED');
    const state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.status).toBe('blocked');
    expect(state.blockedOperations.some((b: any) => b.tool === 'record_audit_hypothesis' && b.code === 'BUDGET_EXCEEDED')).toBe(true);
    expect((await call('run_audit_analysis', { investigationId: id })).isError).toBe(false); // idempotent, already done
    expect((await call('record_audit_hypothesis', hypothesis(id, 'h9', { description: 'z', affectedLocation: 'z' }))).body.error).toBe('INVALID_TRANSITION');
  });

  it('returns deterministic, immutable state', async () => {
    const id = await readyAudit();
    await call('run_audit_analysis', { investigationId: id });
    const a = (await call('get_security_audit_state', { investigationId: id })).body;
    const b = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(a).toEqual(b);
    const first = getSecurityAuditState(id);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    first.data.status = 'completed';
    first.data.hypotheses.push({} as never);
    const second = getSecurityAuditState(id);
    expect(second.ok && second.data.status).not.toBe('completed');
    expect(second.ok && second.data.hypotheses).toHaveLength(0);
  });

  it('redacts secrets from recorded hypotheses and state', async () => {
    const id = await readyAudit();
    const r = await call('record_audit_hypothesis', hypothesis(id, 'h1', { description: 'Token Bearer abcdef.SECRETVALUE99 and key sk-live_ABCDEF123456 appear in a header' }));
    expect(r.text).not.toContain('SECRETVALUE99');
    const state = await call('get_security_audit_state', { investigationId: id });
    expect(state.text).not.toContain('SECRETVALUE99');
    expect(state.text).not.toContain('sk-live_ABCDEF123456');
    expect(state.text).toContain('[REDACTED]');
  });
});

describe('Phase 10 completion, report and remediation availability', () => {
  it('keeps an audit incomplete while verification is outstanding', async () => {
    const id = await readyAudit();
    const state = (await call('run_audit_analysis', { investigationId: id })).body;
    expect(state.status).toBe('awaiting_verification');
    expect(state.complete).toBe(false);
    expect(state.remainingWork.join(' ')).toContain('request_audit_verification');
    expect((await call('complete_security_audit', { investigationId: id })).body.error).toBe('INVESTIGATION_INCOMPLETE');
    expect((await call('generate_security_audit_report', { investigationId: id })).body.error).toBe('INVESTIGATION_INCOMPLETE');
    expect((await call('get_security_audit_state', { investigationId: id })).body.status).toBe('awaiting_verification');
  });

  it('completes a clean project and produces the existing report with a traceability map', async () => {
    const id = await readyAudit(emptyConfig);
    const analysed = (await call('run_audit_analysis', { investigationId: id }, emptyConfig)).body;
    expect(analysed.status).toBe('investigating');
    expect(analysed.remainingWork.join(' ')).toContain('complete_security_audit');
    const plan = (await call('plan_security_investigation', { investigationId: id }, emptyConfig)).body;
    expect(plan.capabilities.find((c: any) => c.kind === 'controlled_remediation').status).toBe('unavailable');
    const done = (await call('complete_security_audit', { investigationId: id }, emptyConfig)).body;
    expect(done.status).toBe('completed');
    expect(done.complete).toBe(true);
    expect(done.remainingWork).toEqual([]);
    expect((await call('complete_security_audit', { investigationId: id }, emptyConfig)).body.status).toBe('completed');
    const after = (await call('plan_security_investigation', { investigationId: id }, emptyConfig)).body;
    expect(after.capabilities.find((c: any) => c.kind === 'controlled_remediation').status).toBe('available');
    const report = await call('generate_security_audit_report', { investigationId: id }, emptyConfig);
    expect(report.isError).toBe(false);
    expect(report.body.report.investigationId).toBe(id);
    expect(report.body.traceability).toHaveLength(report.body.report.findings.length);
    for (const t of report.body.traceability) if (t.evidence.length > 0) expect(t.auditStepIds.length).toBeGreaterThan(0);
  });
});

describe('Phase 10 safety by construction', () => {
  it('contains no shell, network, file-write, or model-API code', () => {
    const dir = fileURLToPath(new URL('../../src/orchestration', import.meta.url));
    const forbidden = /child_process|node:fs|writeFile|appendFile|\.rm\(|unlink|rename\(|fetch\(|process\.env|openai|anthropic|apiKey/i;
    for (const file of fs.readdirSync(dir)) {
      expect(forbidden.test(fs.readFileSync(path.join(dir, file), 'utf8')), file).toBe(false);
    }
  });
});
