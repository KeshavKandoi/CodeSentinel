import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { AppConfig } from '../../src/config.js';
import { scanProject } from '../../src/security/scanner.js';
import { proveSecurityFinding, resetSecurityProofsForTests } from '../../src/proof/engine.js';
import { toolDefinitions } from '../../src/tools/registry.js';

const roots: string[] = [];
const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});
const source = "const app = require('express')();\napp.get('/products/:id', (req, res) => {\n  const product = Product.findById(req.params.id);\n  res.json(product);\n});\n";
const hash = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

function fixture(contents = source, file = 'app.js') {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-sweep-')));
  roots.push(root);
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'sweep-fixture', version: '1.0.0', dependencies: { express: '^4.18.0', axios: '^1.6.0' } }));
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['add', '.'], { cwd: root });
  execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'baseline'], { cwd: root });
  const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 };
  return { root, target, file, config };
}
async function call(name: string, config: AppConfig, input: Record<string, unknown>) {
  const tool = toolDefinitions.find((item) => item.name === name)!;
  const response = await tool.handler(config, input);
  return { error: response.isError, body: JSON.parse(response.content[0]!.text) as any };
}
async function finding(config: AppConfig, selector: string) {
  const result = await scanProject(config);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('scan failed');
  const item = result.data.findings.find((candidate) => candidate.ruleId === selector || candidate.category === selector);
  expect(item).toBeDefined();
  if (!item) throw new Error('finding missing');
  return item;
}
async function remediate(fx: ReturnType<typeof fixture>, id: string, oldText: string, newText: string) {
  return call('remediate_finding', fx.config, { projectRoot: fx.root, finding: { id, file: fx.file, approval: 'explicitly_approved' }, authorization: { projectRoot: fx.root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true }, strategy: { kind: 'patch', oldText, newText }, dryRun: false });
}
async function proofServer(secure: boolean) {
  const server = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(secure ? 'safe fixture response' : 'CODESENTINEL_PROOF_SQLI_SENTINEL'); });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('missing address');
  return `http://127.0.0.1:${address.port}`;
}
async function replaceServer(origin: string, secure: boolean, status = 200) {
  const previous = servers.pop()!;
  await new Promise<void>((resolve) => previous.close(() => resolve()));
  const server = http.createServer((_req, res) => { res.writeHead(status, { 'content-type': 'text/plain' }); res.end(secure ? 'safe fixture response' : 'CODESENTINEL_PROOF_SQLI_SENTINEL'); });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(Number(new URL(origin).port), '127.0.0.1', resolve));
}

describe('Phase 3 security remediation sweep MCP', () => {
  it('resolves a static finding with a full evidence chain and stays read-only and idempotent', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    const applied = await remediate(fx, original.id, '  const product =', '  if (!req.user) return res.sendStatus(403);\n  const product =');
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const before = [hash(fx.target), hash(path.join(fx.root, 'package.json'))];
    const status = execFileSync('git', ['status', '--porcelain'], { cwd: fx.root, encoding: 'utf8' });
    const first = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    const second = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(first.error).toBe(false);
    expect(first.body.findings.resolved).toHaveLength(1);
    expect(first.body.findings.resolved[0]).toMatchObject({ findingId: original.id, state: 'resolved', evidence: { ruleId: 'CS-NODE-009', validationStatus: 'passed', retest: { result: 'resolved', verification: { verified: true } }, postScanFindingIds: [] } });
    expect(first.body.executionStatus).toBe('not_required');
    expect(first.body.verification.resolvedFindings).toBe(1);
    expect(second.body.findings.resolved).toHaveLength(1);
    expect(second.body.securityStatus).toBe(first.body.securityStatus);
    expect([hash(fx.target), hash(path.join(fx.root, 'package.json'))]).toEqual(before);
    expect(execFileSync('git', ['status', '--porcelain'], { cwd: fx.root, encoding: 'utf8' })).toBe(status);
    expect(fs.existsSync(path.join(fx.root, 'node_modules'))).toBe(false);
  });

  it('correlates a moved finding and reports it still vulnerable', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    await remediate(fx, original.id, "const app = require('express')();", "\nconst app = require('express')();");
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(result.body.findings.stillVulnerable).toHaveLength(1);
    expect(result.body.findings.stillVulnerable[0].evidence.postScanFindingIds).toHaveLength(1);
    expect(result.body.newFindings).toHaveLength(0);
    expect(result.body.securityStatus).toBe('vulnerable');
  });

  it('reports a newly introduced finding separately from the resolved original', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    const changed = source.replace('  const product =', '  if (!req.user) return res.sendStatus(403);\n  res.redirect(req.query.url);\n  const product =');
    const applied = await call('remediate_finding', fx.config, { projectRoot: fx.root, finding: { id: original.id, file: fx.file, approval: 'confirmed' }, authorization: { projectRoot: fx.root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true }, strategy: { kind: 'replace', content: changed }, dryRun: false });
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(result.body.findings.resolved).toHaveLength(1);
    expect(result.body.newFindings.some((item: any) => item.ruleId === 'CS-NODE-015')).toBe(true);
    expect(result.body.securityStatus).toBe('vulnerable');
  });

  it('reports an additional same-rule finding when the original condition remains', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    const applied = await remediate(fx, original.id, '  res.json(product);', '  const second = Product.findById(req.params.id);\n  res.json(product);');
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(result.body.findings.stillVulnerable).toHaveLength(1);
    expect(result.body.newFindings.some((item: any) => item.ruleId === 'CS-NODE-009')).toBe(true);
  });

  it('does not retain stale resolution after an external rollback restores the original condition', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    await remediate(fx, original.id, '  const product =', '  if (!req.user) return res.sendStatus(403);\n  const product =');
    const first = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(first.body.findings.resolved).toHaveLength(1);
    fs.writeFileSync(fx.target, source);
    const after = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(after.body.findings.stillVulnerable).toHaveLength(1);
    expect(after.body.findings.resolved).toHaveLength(0);
  });

  it('blocks missing runtime target and setup failures without claiming resolution', async () => {
    const contents = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    const fx = fixture(contents, 'src/app.ts');
    const original = await finding(fx.config, 'injection');
    await remediate(fx, original.id, 'SELECT * FROM users', 'SELECT id FROM users');
    const missing = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(missing.body).toMatchObject({ securityStatus: 'inconclusive', executionStatus: 'blocked', verification: { blocked: true } });
    expect(missing.body.findings.blocked).toHaveLength(1);
    expect(missing.body.blockers[0].kind).toBe('runtime_target_missing');
    const failure = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root, runtimeSetupFailure: { command: 'npm run dev', output: 'EACCES: permission denied in _cacache' } });
    expect(failure.body).toMatchObject({ securityStatus: 'inconclusive', executionStatus: 'blocked' });
    expect(failure.body.blockers[0].kind).toBe('npm_cache_permissions');
    expect(failure.body.findings.resolved).toHaveLength(0);
  });

  it('keeps unsupported and missing-baseline findings from becoming secure', async () => {
    const fx = fixture('const value = true;\n');
    await remediate(fx, 'unbacked-id', 'true', 'false');
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root });
    expect(result.body.findings.unsupported).toHaveLength(1);
    expect(result.body.securityStatus).toBe('inconclusive');
    const empty = fixture();
    const noBaseline = await call('security_remediation_sweep', empty.config, { projectRoot: empty.root });
    expect(noBaseline.body.securityStatus).toBe('inconclusive');
    expect(noBaseline.body.findings.resolved).toHaveLength(0);
  });

  it('rejects malformed IDs, traversal, symlinked roots, and cross-project remediation IDs', async () => {
    const a = fixture();
    const b = fixture();
    const original = await finding(a.config, 'CS-NODE-009');
    const applied = await remediate(a, original.id, '  const product =', '  if (!req.user) return res.sendStatus(403);\n  const product =');
    expect((await call('security_remediation_sweep', a.config, { projectRoot: a.root, findingIds: ['../bad'] })).error).toBe(true);
    expect((await call('security_remediation_sweep', a.config, { projectRoot: a.root, remediationIds: ['bad'] })).error).toBe(true);
    expect((await call('security_remediation_sweep', a.config, { projectRoot: '../outside' })).error).toBe(true);
    const alias = path.join(os.tmpdir(), `cs-sweep-link-${crypto.randomUUID()}`);
    fs.symlinkSync(a.root, alias);
    try { expect((await call('security_remediation_sweep', a.config, { projectRoot: alias })).error).toBe(true); }
    finally { fs.rmSync(alias); }
    const foreign = await call('security_remediation_sweep', b.config, { projectRoot: b.root, remediationIds: [applied.body.remediationId] });
    expect(foreign.body.error).toBe('REMEDIATION_NOT_FOUND');
  });

  it('rejects a superseded remediation ID instead of retesting a newer patch under the old ID', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    const first = await remediate(fx, original.id, "const app = require('express')();", "\nconst app = require('express')();");
    expect(first.body.remediationStatus).toBe('validated_pending_retest');
    execFileSync('git', ['add', '.'], { cwd: fx.root });
    execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'first authorized edit'], { cwd: fx.root });
    const second = await remediate(fx, original.id, '  res.json(product);', '  res.json(product);\n');
    expect(second.body.remediationStatus).toBe('validated_pending_retest');
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root, remediationIds: [first.body.remediationId] });
    expect(result.body.error).toBe('REMEDIATION_CONFLICT');
  });

  it('uses the original runtime proof to distinguish resolved, exploitable, and inconclusive', async () => {
    const contents = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    for (const scenario of ['resolved', 'still_vulnerable', 'inconclusive'] as const) {
      const fx = fixture(contents, 'src/app.ts');
      const original = await finding(fx.config, 'injection');
      const origin = await proofServer(scenario === 'inconclusive');
      const target = { allowedOrigin: origin, minRequestIntervalMs: 0 };
      if (scenario !== 'inconclusive') {
        const proven = await proveSecurityFinding(fx.config, { findingId: original.id, target });
        expect(proven.ok && proven.data.status).toBe('verified');
      }
      await remediate(fx, original.id, 'SELECT * FROM users', 'SELECT id FROM users');
      if (scenario === 'resolved') await replaceServer(origin, true);
      const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root, target });
      expect(result.error).toBe(false);
      const item = [...result.body.findings.resolved, ...result.body.findings.stillVulnerable, ...result.body.findings.inconclusive].find((candidate: any) => candidate.findingId === original.id);
      expect(item?.state).toBe(scenario);
      if (scenario === 'resolved') expect(item.evidence.retest.evidence.method).toBe('runtime_proof_replay');
      if (scenario === 'inconclusive') expect(result.body.securityStatus).toBe('inconclusive');
    }
  });

  it('keeps a disappeared route inconclusive even when the old proof marker is absent', async () => {
    const contents = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    const fx = fixture(contents, 'src/app.ts');
    const original = await finding(fx.config, 'injection');
    const origin = await proofServer(false);
    const target = { allowedOrigin: origin, minRequestIntervalMs: 0 };
    const proven = await proveSecurityFinding(fx.config, { findingId: original.id, target });
    expect(proven.ok && proven.data.status).toBe('verified');
    await remediate(fx, original.id, "app.get('/search'", "app.get('/renamed'");
    await replaceServer(origin, true, 404);
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root, target });
    expect(result.body.findings.inconclusive).toHaveLength(1);
    expect(result.body.findings.resolved).toHaveLength(0);
  });

  it('does not resolve when the trusted before-proof receipt is unavailable', async () => {
    const contents = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    const fx = fixture(contents, 'src/app.ts');
    const original = await finding(fx.config, 'injection');
    const origin = await proofServer(false);
    const target = { allowedOrigin: origin, minRequestIntervalMs: 0 };
    const proven = await proveSecurityFinding(fx.config, { findingId: original.id, target });
    expect(proven.ok && proven.data.status).toBe('verified');
    await remediate(fx, original.id, 'SELECT * FROM users', 'SELECT id FROM users');
    resetSecurityProofsForTests();
    await replaceServer(origin, true);
    const result = await call('security_remediation_sweep', fx.config, { projectRoot: fx.root, target });
    expect(result.body.findings.inconclusive).toHaveLength(1);
    expect(result.body.findings.resolved).toHaveLength(0);
  });
});
