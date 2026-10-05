import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import type { AppConfig } from '../../src/config.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { applyRemediation } from '../../src/remediation/engine.js';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
const digest = (value: string | Buffer) => crypto.createHash('sha256').update(value).digest('hex');
const source = 'const vulnerable = true;\n';

function fixture(): { root: string; config: AppConfig; target: string; unrelated: string } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-remediation-')));
  roots.push(root);
  const target = path.join(root, 'test.js');
  const unrelated = path.join(root, 'notes.txt');
  fs.writeFileSync(target, source);
  fs.writeFileSync(unrelated, 'initial notes\n');
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'controlled-test', version: '1.0.0' }));
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['add', '.'], { cwd: root });
  execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'baseline'], { cwd: root });
  return { root, config: { projectRoot: '', commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 }, target, unrelated };
}

function authorization(root: string) { return { projectRoot: root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true }; }
async function call(name: string, config: AppConfig, input: Record<string, unknown>) {
  const tool = toolDefinitions.find((item) => item.name === name)!;
  const response = await tool.handler(config, input);
  return { error: response.isError, body: JSON.parse(response.content[0]!.text) as any };
}
const input = (root: string, extra: Record<string, unknown> = {}) => ({
  projectRoot: root,
  finding: { id: 'approved-test-finding', file: 'test.js', approval: 'explicitly_approved' },
  strategy: { kind: 'patch', oldText: 'true', newText: 'false' },
  dryRun: false,
  authorization: authorization(root),
  ...extra,
});

describe('controlled remediation MCP boundary', () => {
  it('keeps scan and full audit read-only', async () => {
    const fx = fixture();
    const before = digest(fs.readFileSync(fx.target));
    expect((await call('scan_project', fx.config, { projectRoot: fx.root })).error).toBe(false);
    expect((await call('run_full_security_audit', fx.config, { projectRoot: fx.root })).error).toBe(false);
    expect(digest(fs.readFileSync(fx.target))).toBe(before);
  });

  it('dry-runs a narrow patch without changing the target', async () => {
    const fx = fixture();
    const receipt = await call('remediate_finding', fx.config, input(fx.root, { dryRun: true }));
    expect(receipt.error).toBe(false);
    expect(receipt.body).toMatchObject({ remediationStatus: 'dry_run', validationStatus: 'passed', filesChanged: [], rollbackStatus: 'not_needed' });
    expect(receipt.body.preChangeHashes['test.js']).toBe(digest(source));
    expect(receipt.body.postChangeHashes['test.js']).toBe(digest(source));
    expect(fs.readFileSync(fx.target, 'utf8')).toBe(source);
  });

  it('requires explicit authorization and rejects a different root', async () => {
    const fx = fixture();
    const missing = await call('remediate_finding', fx.config, input(fx.root, { authorization: undefined }));
    expect(missing.body).toMatchObject({ remediationStatus: 'not_authorized', authorizationStatus: 'missing', filesChanged: [] });
    const wrong = await call('remediate_finding', fx.config, input(fx.root, { authorization: authorization(path.dirname(fx.root)) }));
    expect(wrong.body.remediationStatus).toBe('authorization_rejected');
    expect(fs.readFileSync(fx.target, 'utf8')).toBe(source);
  });

  it('applies only the requested file and preserves unrelated pre-existing modifications', async () => {
    const fx = fixture();
    fs.writeFileSync(fx.unrelated, 'user changed notes\n');
    const receipt = await call('remediate_finding', fx.config, input(fx.root));
    expect(receipt.error).toBe(false);
    expect(receipt.body).toMatchObject({ remediationStatus: 'validated_pending_retest', validationStatus: 'passed', rollbackStatus: 'not_needed', filesChanged: ['test.js'] });
    expect(receipt.body.preChangeHashes['test.js']).toBe(digest(source));
    expect(receipt.body.postChangeHashes['test.js']).toBe(digest('const vulnerable = false;\n'));
    expect(receipt.body.gitStatusBefore.modifiedPaths).toContain('notes.txt');
    expect(receipt.body.gitStatusBefore.targetPreModified).toBe(false);
    expect(fs.readFileSync(fx.unrelated, 'utf8')).toBe('user changed notes\n');
    expect(JSON.stringify(receipt.body)).not.toContain(source.trim());
  });

  it('rejects traversal and pre-existing target changes', async () => {
    const fx = fixture();
    const outside = await call('remediate_finding', fx.config, input(fx.root, { finding: { id: 'x', file: '../outside.js', approval: 'explicitly_approved' } }));
    expect(outside.body).toMatchObject({ remediationStatus: 'authorization_rejected', filesChanged: [] });
    fs.writeFileSync(fx.target, 'const userChange = true;\n');
    const dirty = await call('remediate_finding', fx.config, input(fx.root));
    expect(dirty.body).toMatchObject({ remediationStatus: 'authorization_rejected', filesChanged: [] });
    expect(fs.readFileSync(fx.target, 'utf8')).toBe('const userChange = true;\n');
  });

  it('rejects a symlinked target without reading or writing its destination', async () => {
    const fx = fixture();
    const outside = path.join(os.tmpdir(), `cs-outside-${crypto.randomUUID()}.js`);
    fs.writeFileSync(outside, 'const outside = true;\n');
    try {
      fs.rmSync(fx.target);
      fs.symlinkSync(outside, fx.target);
      execFileSync('git', ['add', 'test.js'], { cwd: fx.root });
      execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'record test symlink'], { cwd: fx.root });
      const receipt = await call('remediate_finding', fx.config, input(fx.root));
      expect(receipt.body.filesChanged).toEqual([]);
      expect(receipt.body.remediationStatus).toBe('authorization_rejected');
      expect(fs.readFileSync(outside, 'utf8')).toBe('const outside = true;\n');
    } finally { fs.rmSync(outside, { force: true }); }
  });

  it('rolls back invalid JavaScript and verifies the original hash', async () => {
    const fx = fixture();
    fs.writeFileSync(fx.unrelated, 'user changed notes\n');
    const receipt = await call('remediate_finding', fx.config, input(fx.root, { strategy: { kind: 'patch', oldText: 'true;', newText: 'true + ;' } }));
    expect(receipt.error).toBe(false);
    expect(receipt.body).toMatchObject({ remediationStatus: 'rolled_back', validationStatus: 'failed', rollbackStatus: 'succeeded', filesChanged: [] });
    expect(receipt.body.preChangeHashes['test.js']).toBe(digest(source));
    expect(receipt.body.postChangeHashes['test.js']).toBe(digest(source));
    expect(digest(fs.readFileSync(fx.target))).toBe(digest(source));
    expect(fs.readFileSync(fx.unrelated, 'utf8')).toBe('user changed notes\n');
  });

  it('keeps the legacy apply tool write-protected without authorization', async () => {
    const fx = fixture();
    const result = await applyRemediation({ ...fx.config, projectRoot: fx.root }, 'missing-proposal');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('AUTHORIZATION_REQUIRED');
    expect(fs.readFileSync(fx.target, 'utf8')).toBe(source);
  });
});
