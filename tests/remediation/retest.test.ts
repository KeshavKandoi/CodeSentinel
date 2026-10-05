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
import { proveSecurityFinding } from '../../src/proof/engine.js';
import { toolDefinitions } from '../../src/tools/registry.js';

const roots: string[] = [];
const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});
const digest = (value: Buffer) => crypto.createHash('sha256').update(value).digest('hex');
const staticSource = "const app = require('express')();\napp.get('/products/:id', (req, res) => {\n  const product = Product.findById(req.params.id);\n  res.json(product);\n});\n";

function fixture(source = staticSource, file = 'app.js'): { root: string; config: AppConfig; target: string; file: string } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-retest-')));
  roots.push(root);
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, source);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'retest-fixture', version: '1.0.0', dependencies: { express: '^4.18.0', axios: '^1.6.0' } }));
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['add', '.'], { cwd: root });
  execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'baseline'], { cwd: root });
  return { root, config: { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 1000 }, target, file };
}
async function call(name: string, config: AppConfig, input: Record<string, unknown>) {
  const tool = toolDefinitions.find((item) => item.name === name)!;
  const response = await tool.handler(config, input);
  return { error: response.isError, body: JSON.parse(response.content[0]!.text) as any };
}
async function finding(config: AppConfig, ruleId: string) {
  const scan = await scanProject(config);
  expect(scan.ok).toBe(true);
  if (!scan.ok) throw new Error('scan failed');
  const found = scan.data.findings.find((item) => item.ruleId === ruleId || item.category === ruleId);
  expect(found).toBeDefined();
  if (!found) throw new Error(`missing ${ruleId}`);
  return found;
}
function authorization(root: string) { return { projectRoot: root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true }; }
async function remediate(fx: ReturnType<typeof fixture>, findingId: string, oldText: string, newText: string) {
  return call('remediate_finding', fx.config, { projectRoot: fx.root, finding: { id: findingId, file: fx.file, approval: 'explicitly_approved' }, strategy: { kind: 'patch', oldText, newText }, dryRun: false, authorization: authorization(fx.root) });
}
async function runtimeServer(secure: boolean) {
  const server = http.createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end(secure ? 'safe fixture response' : 'CODESENTINEL_PROOF_SQLI_SENTINEL'); });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('missing address');
  return `http://127.0.0.1:${address.port}`;
}

describe('controlled fix and retest MCP lifecycle', () => {
  it('resolves the original static rule only after independent retest', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    const applied = await remediate(fx, original.id, '  const product =', '  if (!req.user) return res.sendStatus(403);\n  const product =');
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const beforeRetest = digest(fs.readFileSync(fx.target));
    const result = await call('retest_finding', fx.config, { projectRoot: fx.root, findingId: original.id });
    expect(result.error).toBe(false);
    expect(result.body).toMatchObject({ findingId: original.id, result: 'resolved', retestStatus: 'completed', verification: { attempted: true, completed: true, verified: true }, before: { ruleId: 'CS-NODE-009', status: 'present' }, after: { status: 'absent' }, evidence: { method: 'static_rule_retest', filesChecked: 1 } });
    expect(digest(fs.readFileSync(fx.target))).toBe(beforeRetest);
  });

  it('keeps a finding present when validation passes and its line moves', async () => {
    const fx = fixture();
    const original = await finding(fx.config, 'CS-NODE-009');
    const applied = await remediate(fx, original.id, "const app = require('express')();", "\nconst app = require('express')();");
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const beforeRetest = digest(fs.readFileSync(fx.target));
    const result = await call('retest_finding', fx.config, { projectRoot: fx.root, findingId: original.id });
    expect(result.body).toMatchObject({ findingId: original.id, result: 'still_present', verification: { attempted: true, completed: true, verified: false }, after: { status: 'present', ruleId: 'CS-NODE-009' } });
    expect(result.body.after.line).toBeGreaterThan(result.body.before.line);
    expect(digest(fs.readFileSync(fx.target))).toBe(beforeRetest);
  });

  it('blocks proof-eligible retest without an authorized runtime target', async () => {
    const source = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    const fx = fixture(source, 'src/app.ts');
    const original = await finding(fx.config, 'injection');
    const applied = await remediate(fx, original.id, 'SELECT * FROM users', 'SELECT id FROM users');
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const result = await call('retest_finding', fx.config, { projectRoot: fx.root, findingId: original.id });
    expect(result.body.before).toMatchObject({ origin: 'security_scan', proofSupport: 'runtime' });
    expect(result.body).toMatchObject({ retestStatus: 'blocked', result: 'inconclusive', securityStatus: 'inconclusive', executionStatus: 'blocked', verification: { attempted: false, completed: false, blocked: true }, blocker: { kind: 'runtime_target_missing', responsibility: 'user_environment' } });
  });

  it('reports unsupported findings without asserting a fix', async () => {
    const fx = fixture('const value = true;\n');
    const applied = await remediate(fx, 'unbacked-id', 'true', 'false');
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const result = await call('retest_finding', fx.config, { projectRoot: fx.root, findingId: 'unbacked-id' });
    expect(result.body).toMatchObject({ result: 'not_verifiable', verification: { verified: false } });
  });

  it('keeps a proof-eligible finding inconclusive when no trusted before proof exists', async () => {
    const source = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    const fx = fixture(source, 'src/app.ts');
    const original = await finding(fx.config, 'injection');
    const applied = await remediate(fx, original.id, 'SELECT * FROM users', 'SELECT id FROM users');
    expect(applied.body.remediationStatus).toBe('validated_pending_retest');
    const origin = await runtimeServer(true);
    const beforeRetest = digest(fs.readFileSync(fx.target));
    const result = await call('retest_finding', fx.config, { projectRoot: fx.root, findingId: original.id, target: { allowedOrigin: origin, minRequestIntervalMs: 0 } });
    expect(result.body).toMatchObject({ result: 'inconclusive', securityStatus: 'inconclusive', verification: { verified: false } });
    expect(digest(fs.readFileSync(fx.target))).toBe(beforeRetest);
  });

  it('rejects malformed IDs and isolates remediation records by project', async () => {
    const a = fixture();
    const b = fixture();
    const original = await finding(a.config, 'CS-NODE-009');
    await remediate(a, original.id, '  const product =', '  if (!req.user) return res.sendStatus(403);\n  const product =');
    expect((await call('retest_finding', a.config, { projectRoot: a.root, findingId: '../bad' })).error).toBe(true);
    const isolated = await call('retest_finding', b.config, { projectRoot: b.root, findingId: original.id });
    expect(isolated.body.error).toBe('REMEDIATION_NOT_FOUND');
  });

  it('replays trusted runtime proof to classify resolved and still exploitable cases', async () => {
    const source = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable/src/app.ts', import.meta.url)), 'utf8');
    for (const secure of [true, false]) {
      const fx = fixture(source, 'src/app.ts');
      const original = await finding(fx.config, 'injection');
      const origin = await runtimeServer(false);
      const target = { allowedOrigin: origin, minRequestIntervalMs: 0 };
      const initial = await proveSecurityFinding(fx.config, { findingId: original.id, target, sessions: [], sessionParams: {} });
      expect(initial.ok).toBe(true);
      if (!initial.ok) continue;
      expect(initial.data.status, initial.data.limitation ?? 'unexpected proof status').toBe('verified');
      const applied = await remediate(fx, original.id, 'SELECT * FROM users', 'SELECT id FROM users');
      expect(applied.body.remediationStatus).toBe('validated_pending_retest');
      if (secure) {
        const server = servers.pop()!;
        await new Promise<void>((resolve) => server.close(() => resolve()));
        const replacement = http.createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('safe fixture response'); });
        servers.push(replacement);
        await new Promise<void>((resolve) => replacement.listen(Number(new URL(origin).port), '127.0.0.1', resolve));
      }
      const beforeRetest = digest(fs.readFileSync(fx.target));
      const result = await call('retest_finding', fx.config, { projectRoot: fx.root, findingId: original.id, target });
      expect(result.error).toBe(false);
      expect(result.body.result).toBe(secure ? 'resolved' : 'still_present');
      expect(result.body.evidence.method).toBe('runtime_proof_replay');
      expect(digest(fs.readFileSync(fx.target))).toBe(beforeRetest);
    }
  });
});
