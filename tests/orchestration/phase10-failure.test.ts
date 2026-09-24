import { beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';
import type { AppConfig } from '../../src/config.js';

// Synthetic fault injection: route discovery fails, so the deterministic analysis fails.
vi.mock('../../src/routes/engine.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/routes/engine.js')>();
  return { ...actual, discoverRoutes: () => ({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'synthetic route discovery failure' } }) };
});

const FIXTURE = fs.realpathSync(fileURLToPath(new URL('../fixtures/access-control-express', import.meta.url)));
const config: AppConfig = { projectRoot: FIXTURE, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };

async function call(name: string, args: unknown) {
  const tool = toolDefinitions.find((t) => t.name === name)!;
  const response = await tool.handler(config, args);
  return { isError: response.isError, body: JSON.parse(response.content[0]!.text) as Record<string, any> };
}

beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });

describe('Phase 10 failed investigations', () => {
  it('marks the audit failed, stays incomplete, and refuses every further step', async () => {
    const id = (await call('start_security_audit', { objective: 'General security review' })).body.investigationId as string;
    await call('plan_security_investigation', { investigationId: id });
    const run = await call('run_audit_analysis', { investigationId: id });
    expect(run.isError).toBe(true);
    expect(run.body.error).toBe('ANALYSIS_FAILED');
    const state = (await call('get_security_audit_state', { investigationId: id })).body;
    expect(state.status).toBe('failed');
    expect(state.complete).toBe(false);
    expect(state.errors.length).toBeGreaterThan(0);
    expect(state.remainingWork.join(' ')).toContain('failed');
    expect(state.steps.find((s: any) => s.tool === 'run_audit_analysis').status).toBe('failed');
    expect((await call('complete_security_audit', { investigationId: id })).body.error).toBe('INVALID_TRANSITION');
    expect((await call('generate_security_audit_report', { investigationId: id })).body.error).toBe('INVESTIGATION_INCOMPLETE');
    expect((await call('record_audit_hypothesis', { investigationId: id, hypothesisId: 'h1', category: 'x', description: 'd', affectedLocation: 'l', reason: 'r' })).body.error).toBe('INVALID_TRANSITION');
  });
});
