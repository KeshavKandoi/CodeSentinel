import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { getSecurityAuditState, resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const CLEAN = fs.realpathSync(fileURLToPath(new URL('../fixtures/generic-node', import.meta.url)));
const SECURITY = fs.realpathSync(fileURLToPath(new URL('../fixtures/security-cases', import.meta.url)));
const config: AppConfig = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
const cleanConfig: AppConfig = { ...config, projectRoot: CLEAN };
const securityConfig: AppConfig = { ...config, projectRoot: SECURITY, maxListResults: 2_000 };

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}
async function call(name: string, input: unknown, cfg = config) {
  const response = await tool(name).handler(cfg, input);
  return { isError: response.isError, text: response.content[0]!.text, body: JSON.parse(response.content[0]!.text) as any };
}
async function start(cfg = config, limits?: Record<string, number>) {
  const response = await call('start_security_audit', { objective: 'Review authorization of the API', focus: 'authorization', ...(limits ? { limits } : {}) }, cfg);
  return response.body.investigationId as string;
}
async function dispatch(investigationId: string, action: string, args: Record<string, unknown> = {}, cfg = config) {
  return call('dispatch_security_action', { investigationId, action, arguments: args }, cfg);
}

beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });

describe('Phase 10 allowlisted action dispatcher', () => {
  it('executes approved actions and records action metadata and evidence', async () => {
    const id = await start();
    const plan = await dispatch(id, 'plan_security_investigation');
    expect(plan.isError).toBe(false);
    expect(plan.body.action).toBe('plan_security_investigation');
    const analysis = await dispatch(id, 'run_audit_analysis');
    expect(analysis.isError).toBe(false);
    const state = await call('get_security_audit_state', { investigationId: id });
    const step = state.body.steps.find((item: any) => item.actionName === 'run_audit_analysis');
    expect(step.resultStatus).toBe('completed');
    expect(step.durationMs).toBeTypeOf('number');
    expect(step.evidenceCount).toBeGreaterThan(0);
    expect(step.evidenceRefs.length).toBeGreaterThan(0);
    expect(step.inputSummary).toBe('{}');
    expect(analysis.body.data.evidenceRefs.total).toBeGreaterThan(0);
  });

  it('rejects unknown, malformed, mutating, shell, and path-traversal actions', async () => {
    const id = await start();
    expect((await call('dispatch_security_action', { investigationId: id, action: 'run_command', arguments: { command: 'rm -rf /' } })).body.error).toBe('INVALID_INPUT');
    expect((await call('dispatch_security_action', { investigationId: id, action: 'apply_remediation', arguments: {} })).body.error).toBe('INVALID_INPUT');
    expect((await call('dispatch_security_action', { investigationId: id, action: 'list_files', arguments: { path: '../../etc' } })).body.error).toBe('PATH_OUTSIDE_ROOT');
    const malformed = await dispatch(id, 'read_file', { path: 123 });
    expect(malformed.body.error).toBe('INVALID_INPUT');
    const writeAttempt = await call('dispatch_security_action', { investigationId: id, action: 'write_file', arguments: { path: 'x', content: 'changed' } });
    expect(writeAttempt.body.error).toBe('INVALID_INPUT');
    const state = await call('get_security_audit_state', { investigationId: id });
    expect(state.body.steps.some((item: any) => item.actionName === 'list_files' && item.failure.code === 'PATH_OUTSIDE_ROOT')).toBe(true);
  });

  it('rejects duplicate actions and enforces step limits', async () => {
    const id = await start(config, { maxSteps: 3 });
    expect((await dispatch(id, 'plan_security_investigation')).isError).toBe(false);
    expect((await dispatch(id, 'plan_security_investigation')).body.error).toBe('DUPLICATE_OPERATION');
    expect((await dispatch(id, 'run_audit_analysis')).isError).toBe(false);
    expect((await dispatch(id, 'get_project_info')).isError).toBe(false);
    const third = await dispatch(id, 'list_files');
    expect(third.body.error).toBe('BUDGET_EXCEEDED');
    const state = await call('get_security_audit_state', { investigationId: id });
    expect(state.body.status).toBe('blocked');
  });

  it('propagates blocked runtime verification and preserves candidate status', async () => {
    const id = await start();
    await dispatch(id, 'plan_security_investigation');
    const analysis = await dispatch(id, 'run_audit_analysis');
    const finding = analysis.body.data.findings.find((item: any) => item.origin === 'access_control');
    expect(finding).toBeDefined();
    const hypothesis = await dispatch(id, 'record_audit_hypothesis', {
      hypothesisId: 'dispatch-h1', category: 'missing_authentication', description: 'Candidate requires verification.', affectedLocation: 'admin route', reason: 'Static route analysis', findingId: finding.findingId,
    });
    expect(hypothesis.isError).toBe(false);
    const blocked = await dispatch(id, 'request_audit_verification', { hypothesisId: 'dispatch-h1', findingId: finding.findingId, target: { allowedOrigin: 'http://10.0.0.4:3000' } });
    expect(blocked.isError).toBe(false);
    expect(blocked.body.status).toBe('blocked');
    const state = await call('get_security_audit_state', { investigationId: id });
    expect(state.body.blockedOperations.length).toBeGreaterThan(0);
    expect(state.body.findings.find((item: any) => item.findingId === finding.findingId).lifecycle).not.toBe('runtime_verified');
  });

  it('completes a dispatcher-driven clean workflow and bounds action output', async () => {
    const id = await start(cleanConfig, { maxOutputBytes: 8_000, maxSteps: 8 });
    expect((await dispatch(id, 'plan_security_investigation', {}, cleanConfig)).isError).toBe(false);
    expect((await dispatch(id, 'run_audit_analysis', {}, cleanConfig)).isError).toBe(false);
    const done = await dispatch(id, 'complete_security_audit', {}, cleanConfig);
    expect(done.isError).toBe(false);
    expect(done.body.data.status).toBe('completed');
    const report = await dispatch(id, 'generate_security_audit_report', {}, cleanConfig);
    expect(report.isError).toBe(false);
    const state = getSecurityAuditState(id);
    expect(state.ok).toBe(true);
    if (state.ok) {
      expect(state.data.steps.some((step) => step.actionName === 'generate_security_audit_report')).toBe(true);
      expect(Buffer.byteLength(JSON.stringify(state.data), 'utf8')).toBeLessThanOrEqual(8_000);
    }
  });

  it('rejects an approved action whose bounded result is too large', async () => {
    const id = await start(securityConfig, { maxOutputBytes: 8_000 });
    const result = await dispatch(id, 'scan_project', {}, securityConfig);
    expect(result.isError).toBe(true);
    expect(result.body.error).toBe('BUDGET_EXCEEDED');
    const state = await call('get_security_audit_state', { investigationId: id }, securityConfig);
    const step = state.body.steps.find((item: any) => item.actionName === 'scan_project');
    expect(step.resultStatus).toBe('blocked');
    expect(step.failure.code).toBe('BUDGET_EXCEEDED');
  });
});
