import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AppConfig } from '../../src/config.js';
import { classifyRuntimeSetupFailure } from '../../src/audit/environment.js';
import { toolDefinitions } from '../../src/tools/registry.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

function project(source: string): string {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-status-')));
  roots.push(root);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'status-test', version: '1.0.0', dependencies: { express: '^4.0.0' } }));
  fs.writeFileSync(path.join(root, 'app.js'), source);
  return root;
}

async function audit(root: string, runtimeSetupFailure?: { command: string; output: string }) {
  const config: AppConfig = { projectRoot: '', commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 };
  const tool = toolDefinitions.find((item) => item.name === 'run_full_security_audit')!;
  const result = await tool.handler(config, { projectRoot: root, runtimeSetupFailure });
  expect(result.isError).toBe(false);
  return JSON.parse(result.content[0]!.text);
}

describe('runtime setup status', () => {
  it.each([
    ['npm cache EPERM', 'npm ci', 'EPERM: operation not permitted, open ~/.npm/_cacache/index', 'npm_cache_permissions'],
    ['npm cache EACCES', 'npm ci', 'EACCES: permission denied, open ~/.npm/_cacache/index', 'npm_cache_permissions'],
    ['missing dependency', 'npm ci', 'missing dependency express', 'missing_dependency'],
    ['module resolution', 'node app.js', 'Error: Cannot find module express', 'module_resolution'],
    ['MongoDB unavailable', 'node app.js', 'MongoDB connection refused at 127.0.0.1:27017', 'database_unavailable'],
    ['port occupied', 'node app.js', 'EADDRINUSE: address already in use', 'port_in_use'],
    ['Docker unavailable', 'docker compose up', 'docker daemon not running', 'docker_unavailable'],
    ['missing variable', 'node app.js', 'missing environment variable DATABASE_URL', 'missing_variable'],
    ['missing executable', 'node app.js', 'spawn node ENOENT', 'missing_executable'],
    ['missing runtime', 'start app', 'required runtime unavailable', 'missing_runtime'],
    ['invalid configuration', 'node app.js', 'invalid project config', 'invalid_configuration'],
    ['filesystem permission denied', 'node app.js', 'permission denied opening working directory', 'filesystem_permissions'],
  ])('classifies %s as setup failure', (_label, command, output, kind) => {
    const result = classifyRuntimeSetupFailure(command, output);
    expect(result.kind).toBe(kind);
    expect(result.reason).toMatch(/Runtime verification could not start/);
    expect(result.recommendedNextStep.length).toBeGreaterThan(0);
  });

  it('returns a blocked MCP audit with static candidates and no false security conclusion', async () => {
    const root = project("const express = require('express'); const app = express(); app.get('/admin', (req, res) => res.send('admin'));\n");
    const before = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
    const result = await audit(root, { command: 'npm ci', output: 'EPERM: operation not permitted, open ~/.npm/_cacache/private-marker' });
    expect(result.executionStatus).toBe('blocked');
    expect(result.securityStatus).toBe('inconclusive');
    expect(result.blocker.kind).toBe('npm_cache_permissions');
    expect(result.summary.total).toBeGreaterThan(0);
    expect(result.verification).toMatchObject({ attempted: false, completed: false, blocked: true, verifiedVulnerabilities: 0 });
    expect(result.verification.staticCandidatesUnverified).toBeGreaterThan(0);
    expect(result.issues.some((issue: any) => issue.code === 'ENVIRONMENT_BLOCKED')).toBe(true);
    expect(result.guidance.couldNotVerify.join(' ')).toContain('static candidate');
    expect(result.targetActivity).toMatchObject({ targetModifications: 'none', dependenciesInstalled: false, commandsExecutedInsideTarget: false, runtimeStartedByCodeSentinel: false, networkRequestsSent: false, databaseAccessed: false });
    expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toBe(before);
    expect(JSON.stringify(result)).not.toContain('0 vulnerabilities');
    expect(JSON.stringify(result)).not.toContain('private-marker');
  });

  it('reports no findings with blocked verification as inconclusive', async () => {
    const result = await audit(project('const value = 1;\n'), { command: 'npm ci', output: 'EACCES: permission denied in ~/.npm/_cacache' });
    expect(result.summary.total).toBe(0);
    expect(result.executionStatus).toBe('blocked');
    expect(result.securityStatus).toBe('inconclusive');
  });

  it('reports an ordinary static-only audit without claiming runtime safety', async () => {
    const result = await audit(project('const value = 1;\n'));
    expect(result.executionStatus).toBe('partially_completed');
    expect(result.verification.attempted).toBe(false);
    expect(result.securityStatus).not.toBe('verified_safe');
  });
});
