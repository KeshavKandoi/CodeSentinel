import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const source = "const app = require('express')();\napp.get('/products/:id', (req, res) => {\n  const product = Product.findById(req.params.id);\n  res.json(product);\n});\n";
const digest = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

describe('built MCP controlled remediation lifecycle', () => {
  let root = '';
  let otherRoot = '';
  let target = '';
  let child: ChildProcessWithoutNullStreams;
  let buffer = '';
  let nextId = 1;
  const pending = new Map<number, (value: any) => void>();

  function request(method: string, params: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`MCP response timed out for ${method}`)); }, 30_000);
      pending.set(id, (value) => { clearTimeout(timer); pending.delete(id); resolve(value); });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  async function call(name: string, args: Record<string, unknown>) {
    const response = await request('tools/call', { name, arguments: args });
    return { error: response.result.isError as boolean, body: JSON.parse(response.result.content[0].text) as any };
  }

  beforeAll(async () => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-mcp-remediation-')));
    target = path.join(root, 'app.js');
    fs.writeFileSync(target, source);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'mcp-remediation-fixture', version: '1.0.0', dependencies: { express: '^4.18.0' } }));
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['add', '.'], { cwd: root });
    execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'baseline'], { cwd: root });
    execFileSync('npm', ['run', 'build'], { cwd: path.resolve('.'), stdio: 'pipe' });
    const env = { ...process.env };
    delete env.PROJECT_ROOT;
    child = spawn(process.execPath, [path.resolve('dist', 'index.js')], { cwd: path.resolve('.'), env });
    child.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString();
      let index: number;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (!line) continue;
        try { const message = JSON.parse(line); if (typeof message.id === 'number') pending.get(message.id)?.(message); }
        catch { }
      }
    });
    child.stderr.on('data', () => undefined);
    await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'remediation-test', version: '1.0.0' } });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }, 60_000);

  afterAll(() => {
    child?.kill();
    if (root) fs.rmSync(root, { recursive: true, force: true });
    if (otherRoot) fs.rmSync(otherRoot, { recursive: true, force: true });
  });

  it('executes scan, authorization, rollback, write, retest, audit, and sweep through stdio', async () => {
    const authorization = { projectRoot: root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true };
    const baselineHash = digest(target);
    const baselineGit = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
    const scan = await call('scan_project', { projectRoot: root });
    expect(scan.error).toBe(false);
    const finding = scan.body.findings.find((item: any) => item.ruleId === 'CS-NODE-009');
    expect(finding).toBeDefined();
    const audit = await call('run_full_security_audit', { projectRoot: root });
    expect(audit.error).toBe(false);
    expect(digest(target)).toBe(baselineHash);
    expect(execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' })).toBe(baselineGit);
    const baseInput = { projectRoot: root, finding: { id: finding.id, file: 'app.js', approval: 'explicitly_approved' }, dryRun: false };
    const unauthorized = await call('remediate_finding', { ...baseInput, strategy: { kind: 'patch', oldText: '  const product =', newText: '  if (!req.user) return res.sendStatus(403);\n  const product =' } });
    expect(unauthorized.body.remediationStatus).toBe('not_authorized');
    expect(digest(target)).toBe(baselineHash);
    const invalid = await call('remediate_finding', { ...baseInput, authorization, strategy: { kind: 'patch', oldText: 'res.json(product);', newText: 'res.json(product + );' } });
    expect(invalid.body).toMatchObject({ remediationStatus: 'rolled_back', validationStatus: 'failed', rollbackStatus: 'succeeded' });
    expect(digest(target)).toBe(baselineHash);
    const moved = await call('remediate_finding', { ...baseInput, authorization, strategy: { kind: 'patch', oldText: "const app = require('express')();", newText: "\nconst app = require('express')();" } });
    expect(moved.body).toMatchObject({ remediationStatus: 'validated_pending_retest', validationStatus: 'passed', preChangeHashes: { 'app.js': baselineHash } });
    expect(digest(target)).toBe(moved.body.postChangeHashes['app.js']);
    expect(JSON.stringify(moved.body)).not.toMatch(/"(?:fixed|resolved)"/);
    const movedRetest = await call('retest_finding', { projectRoot: root, findingId: finding.id });
    expect(movedRetest.body).toMatchObject({ result: 'still_present', before: { ruleId: 'CS-NODE-009' }, after: { status: 'present' } });
    expect(movedRetest.body.after.line).toBeGreaterThan(movedRetest.body.before.line);
    const beforeMovedSweep = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
    const movedSweep = await call('security_remediation_sweep', { projectRoot: root });
    expect(movedSweep.body.findings.stillVulnerable).toHaveLength(1);
    expect(movedSweep.body.newFindings).toHaveLength(0);
    expect(execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' })).toBe(beforeMovedSweep);
    execFileSync('git', ['restore', '--', 'app.js'], { cwd: root });
    expect(digest(target)).toBe(baselineHash);
    const fixed = await call('remediate_finding', { ...baseInput, authorization, strategy: { kind: 'patch', oldText: '  const product =', newText: '  if (!req.user) return res.sendStatus(403);\n  res.redirect(req.query.url);\n  const product =' } });
    expect(fixed.body).toMatchObject({ remediationStatus: 'validated_pending_retest', validationStatus: 'passed', preChangeHashes: { 'app.js': baselineHash } });
    const afterWrite = digest(target);
    const retest = await call('retest_finding', { projectRoot: root, findingId: finding.id });
    expect(retest.body).toMatchObject({ result: 'resolved', verification: { attempted: true, completed: true, verified: true }, evidence: { method: 'static_rule_retest' } });
    expect(digest(target)).toBe(afterWrite);
    const postScan = await call('scan_project', { projectRoot: root });
    expect(postScan.body.findings.some((item: any) => item.ruleId === 'CS-NODE-015')).toBe(true);
    const postAudit = await call('run_full_security_audit', { projectRoot: root });
    expect(postAudit.error).toBe(false);
    const sweep = await call('security_remediation_sweep', { projectRoot: root });
    expect(sweep.body.findings.resolved.some((item: any) => item.findingId === finding.id)).toBe(true);
    expect(sweep.body.newFindings.some((item: any) => item.ruleId === 'CS-NODE-015')).toBe(true);
    expect(sweep.body.securityStatus).toBe('vulnerable');
    expect(digest(target)).toBe(afterWrite);
    expect(fs.existsSync(path.join(root, 'node_modules'))).toBe(false);
    otherRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-mcp-remediation-other-')));
    fs.writeFileSync(path.join(otherRoot, 'package.json'), JSON.stringify({ name: 'other-project', version: '1.0.0' }));
    const crossProject = await call('security_remediation_sweep', { projectRoot: otherRoot, remediationIds: [fixed.body.remediationId] });
    expect(crossProject.body.error).toBe('REMEDIATION_NOT_FOUND');
    const runtimeFile = path.join(root, 'runtime.js');
    fs.writeFileSync(runtimeFile, "const app = require('express')();\napp.get('/search', (req, res) => {\n  const rows = db.query(`SELECT * FROM users WHERE name = '${String(req.query.query)}'`);\n  res.json(rows);\n});\n");
    execFileSync('git', ['add', 'runtime.js'], { cwd: root });
    execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'synthetic runtime baseline'], { cwd: root });
    const runtimeScan = await call('scan_project', { projectRoot: root });
    const runtimeFinding = runtimeScan.body.findings.find((item: any) => item.category === 'injection' && item.file === 'runtime.js');
    expect(runtimeFinding).toBeDefined();
    const runtimeChange = await call('remediate_finding', { projectRoot: root, finding: { id: runtimeFinding.id, file: 'runtime.js', approval: 'explicitly_approved' }, authorization, strategy: { kind: 'patch', oldText: 'SELECT * FROM users', newText: 'SELECT id FROM users' }, dryRun: false });
    expect(runtimeChange.body.remediationStatus).toBe('validated_pending_retest');
    const blockedRetest = await call('retest_finding', { projectRoot: root, findingId: runtimeFinding.id });
    expect(blockedRetest.body).toMatchObject({ result: 'inconclusive', retestStatus: 'blocked', blocker: { kind: 'runtime_target_missing' } });
    const blockedSweep = await call('security_remediation_sweep', { projectRoot: root });
    expect(blockedSweep.body.executionStatus).toBe('blocked');
    expect(blockedSweep.body.findings.blocked.some((item: any) => item.findingId === runtimeFinding.id)).toBe(true);
    const setupFailure = await call('security_remediation_sweep', { projectRoot: root, runtimeSetupFailure: { command: 'npm run dev', output: 'missing dependency: express' } });
    expect(setupFailure.body.executionStatus).toBe('blocked');
    expect(setupFailure.body.blockers.some((item: any) => item.kind === 'missing_dependency')).toBe(true);
    expect(fs.existsSync(path.join(root, 'node_modules'))).toBe(false);
    const unsupportedFile = path.join(root, 'unsupported.js');
    fs.writeFileSync(unsupportedFile, 'const syntheticValue = true;\n');
    execFileSync('git', ['add', 'unsupported.js'], { cwd: root });
    execFileSync('git', ['-c', 'user.name=CodeSentinel Test', '-c', 'user.email=test@invalid.local', 'commit', '-qm', 'synthetic unsupported baseline'], { cwd: root });
    const unsupportedChange = await call('remediate_finding', { projectRoot: root, finding: { id: 'synthetic-unsupported', file: 'unsupported.js', approval: 'explicitly_approved' }, authorization, strategy: { kind: 'patch', oldText: 'true', newText: 'false' }, dryRun: false });
    expect(unsupportedChange.body.remediationStatus).toBe('validated_pending_retest');
    const unsupportedRetest = await call('retest_finding', { projectRoot: root, findingId: 'synthetic-unsupported' });
    expect(unsupportedRetest.body.result).toBe('not_verifiable');
    const unsupportedSweep = await call('security_remediation_sweep', { projectRoot: root });
    expect(unsupportedSweep.body.findings.unsupported.some((item: any) => item.findingId === 'synthetic-unsupported')).toBe(true);
  }, 60_000);
});
