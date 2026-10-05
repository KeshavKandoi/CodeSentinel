import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AppConfig } from '../../src/config.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetAuditSessionsForTests } from '../../src/orchestration/engine.js';

const roots: string[] = [];
const config = (projectRoot = ''): AppConfig => ({ projectRoot, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 });
const fixture = (source: string, name = 'audit-fixture'): string => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-explicit-audit-')));
  roots.push(root);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name, version: '1.0.0' }));
  fs.writeFileSync(path.join(root, 'index.js'), source);
  return root;
};
const call = async (name: string, cfg: AppConfig, input: Record<string, unknown>): Promise<{ isError: boolean; body: any }> => {
  const tool = toolDefinitions.find((item) => item.name === name)!;
  const response = await tool.handler(cfg, input);
  return { isError: response.isError, body: JSON.parse(response.content[0].text) };
};
beforeEach(() => { resetInvestigationsForTests(); resetAuditSessionsForTests(); });
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

describe('explicit deep-audit root', () => {
  it('runs the complete pipeline with PROJECT_ROOT unset and separates heuristic signals', async () => {
    const root = fixture("const secret = 'abcdefghijklmno';\nconst hash = require('crypto').createHash('md5');\n");
    const before = fs.readFileSync(path.join(root, 'index.js'), 'utf8');
    const result = await call('run_full_security_audit', config(), { projectRoot: root });
    expect(result.isError).toBe(false);
    expect(result.body.project.name).toBe('audit-fixture');
    expect(result.body.stages.find((stage: any) => stage.stage === 'deep_analysis').status).toBe('completed');
    expect(result.body.summary.total).toBe(result.body.findings.length);
    expect(result.body.reviewSignals.length).toBeGreaterThan(0);
    expect(result.body.summary.reviewSignals).toBe(result.body.reviewSignals.length);
    expect(result.body.reviewSignals.every((finding: any) => finding.sources.every((source: any) => source.ruleId === null))).toBe(true);
    expect(result.body.domainCoverage.every((domain: any) => domain.status !== 'passed')).toBe(true);
    expect(result.body.domainCoverage.some((domain: any) => domain.status === 'unsupported')).toBe(true);
    expect(fs.readFileSync(path.join(root, 'index.js'), 'utf8')).toBe(before);
  });

  it('uses an explicit root over PROJECT_ROOT and rejects missing, traversal, and symlinked roots', async () => {
    const a = fixture('const alpha = true;\n');
    const b = fixture('const beta = true;\n', 'other-fixture');
    expect((await call('run_full_security_audit', config(b), { projectRoot: path.join(a, '.') })).body.project.name).toBe('audit-fixture');
    expect((await call('run_full_security_audit', config(), {})).body.error).toBe('INVALID_INPUT');
    expect((await call('start_security_audit', config(), { objective: 'Review security' })).body.error).toBe('INVALID_INPUT');
    expect((await call('start_security_investigation', config(), { scope: ['general_application_security'], hypothesis: 'Review security' })).body.error).toBe('INVALID_INPUT');
    expect((await call('run_full_security_audit', config(b), {})).body.project.name).toBe('other-fixture');
    expect((await call('run_full_security_audit', config(), { projectRoot: path.join(a, '..', 'no-such-project') })).isError).toBe(true);
    const link = path.join(a, 'link'); fs.symlinkSync(b, link);
    expect((await call('run_full_security_audit', config(), { projectRoot: link })).isError).toBe(true);
  });

  it('does not read an outside source through a symlink during an explicit-root audit', async () => {
    const a = fixture('const safe = true;\n');
    const b = fixture("const outsideMarker = 'unique-outside-project-content';\n");
    fs.symlinkSync(path.join(b, 'index.js'), path.join(a, 'outside.js'));
    const result = await call('run_full_security_audit', config(), { projectRoot: a });
    expect(result.isError).toBe(false);
    expect(JSON.stringify(result.body)).not.toContain('unique-outside-project-content');
    expect(result.body.readOnly.sourceTreeUnchanged).toBe(true);
  });

  it('continues an explicitly rooted audit without PROJECT_ROOT and keeps project sessions isolated', async () => {
    const a = fixture('const alpha = true;\n');
    const b = fixture('const beta = true;\n');
    const start = await call('start_security_audit', config(), { projectRoot: a, objective: 'Review project security' });
    expect(start.isError).toBe(false);
    const id = start.body.investigationId;
    expect((await call('plan_security_investigation', config(), { investigationId: id })).isError).toBe(false);
    const analysis = await call('run_audit_analysis', config(), { investigationId: id });
    expect(analysis.isError).toBe(false);
    expect(analysis.body.completedCapabilities).toContain('run_audit_analysis');
    expect((await call('run_audit_analysis', config(), { investigationId: id, projectRoot: b })).body.error).toBe('PATH_OUTSIDE_ROOT');
    expect((await call('propose_remediation', config(), { investigationId: id, projectRoot: b })).body.error).toBe('PATH_OUTSIDE_ROOT');
  });

  it('starts a direct investigation with an explicit root and keeps the stored canonical path', async () => {
    const root = fixture('const safe = true;\n');
    const started = await call('start_security_investigation', config(), { projectRoot: path.join(root, '.'), scope: ['general_application_security'], hypothesis: 'Review security controls' });
    expect(started.isError).toBe(false);
    expect(started.body.projectPath).toBe(root);
    const id = started.body.id;
    expect((await call('run_security_analysis', config(), { investigationId: id })).isError).toBe(false);
    const other = fixture('const other = true;\n');
    expect((await call('run_security_analysis', config(), { investigationId: id, projectRoot: other })).body.error).toBe('PATH_OUTSIDE_ROOT');
  });

  it('keeps an explicit audit root when PROJECT_ROOT points to a different project', async () => {
    const selected = fixture('const selected = true;\n', 'selected-project');
    const global = fixture('const global = true;\n', 'global-project');
    const start = await call('start_security_audit', config(global), { projectRoot: selected, objective: 'Review selected project security' });
    expect(start.isError).toBe(false);
    const id = start.body.investigationId;
    expect((await call('plan_security_investigation', config(global), { investigationId: id })).isError).toBe(false);
    const analysis = await call('run_audit_analysis', config(global), { investigationId: id });
    expect(analysis.isError).toBe(false);
    const investigation = await call('get_investigation', config(global), { investigationId: id });
    expect(investigation.body.projectPath).toBe(selected);
  });
});
