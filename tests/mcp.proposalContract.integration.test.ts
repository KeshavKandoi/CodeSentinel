import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { proposeRemediationSchema } from '../src/validation/schemas.js';

const vulnerable = "const app = require('express')();\napp.get('/products/:id', (req, res) => {\n  const product = Product.findById(req.params.id);\n  res.json(product);\n});\n";
const repaired = vulnerable.replace('  const product =', '  if (!req.user) return res.sendStatus(403);\n  const product =');
const sha = (content: Buffer | string) => crypto.createHash('sha256').update(content).digest('hex');

describe('built MCP remediation proposal contract', () => {
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
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-proposal-contract-')));
    otherRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-proposal-other-')));
    target = path.join(root, 'app.js');
    fs.writeFileSync(target, vulnerable);
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'proposal-fixture', version: '1.0.0', dependencies: { express: '^4.18.0' } }));
    fs.writeFileSync(path.join(otherRoot, 'package.json'), JSON.stringify({ name: 'other-fixture', version: '1.0.0' }));
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
        try { const message = JSON.parse(line); if (typeof message.id === 'number') pending.get(message.id)?.(message); } catch {}
      }
    });
    child.stderr.on('data', () => undefined);
    await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'proposal-contract-test', version: '1.0.0' } });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }, 60_000);

  afterAll(() => {
    child?.kill();
    if (root) fs.rmSync(root, { recursive: true, force: true });
    if (otherRoot) fs.rmSync(otherRoot, { recursive: true, force: true });
  });

  it('advertises structured changes and completes a guarded proposal, write, retest, and rollback', async () => {
    const listed = await request('tools/list', {});
    const tools = listed.result.tools as Array<{ name: string; inputSchema: any }>;
    const proposalSchema = tools.find((tool) => tool.name === 'propose_remediation')!.inputSchema;
    expect(proposalSchema.properties.files.items).toMatchObject({ type: 'object', required: ['path', 'originalContentHash', 'proposedContent', 'description'] });
    expect(proposalSchema.properties.files.items.properties.originalContentHash.pattern).toBeDefined();
    expect(proposalSchema.allOf).toEqual(expect.arrayContaining([expect.objectContaining({ then: { required: ['runtimeVerification'] } })]));
    expect(tools.find((tool) => tool.name === 'apply_remediation')!.inputSchema.properties.authorization.properties).toHaveProperty('allowRemediation');
    const originalHash = sha(fs.readFileSync(target));
    const packagePath = path.join(root, 'package.json');
    const packageHash = sha(fs.readFileSync(packagePath));
    const scan = await call('scan_project', { projectRoot: root });
    const finding = scan.body.findings.find((item: any) => item.ruleId === 'CS-NODE-009');
    expect(finding).toBeDefined();
    const started = await call('start_security_investigation', { projectRoot: root, projectPath: root, scope: ['input_validation'], hypothesis: 'Check missing route authorization.' });
    expect(started.error).toBe(false);
    const analysis = await call('run_security_analysis', { projectRoot: root, investigationId: started.body.id });
    const investigationFinding = analysis.body.findings.find((item: any) => item.origin === 'security_scan' && item.file === 'app.js' && item.title === 'Broken object authorization indicator');
    expect(investigationFinding).toBeDefined();
    const input = { projectRoot: root, investigationId: started.body.id, findingId: investigationFinding.findingId, description: 'Add a route authorization guard.', rationale: 'Require an authenticated user before looking up the product.', files: [{ path: 'app.js', originalContentHash: originalHash, proposedContent: repaired, description: 'Guard product lookup.' }], expectedSecurityEffect: 'The missing authorization rule no longer matches this route.', requiresRuntimeVerification: false };
    const { projectRoot: _selectedRoot, ...proposalInput } = input;
    expect(proposeRemediationSchema.safeParse(proposalInput).success).toBe(true);
    expect(proposeRemediationSchema.safeParse({ ...proposalInput, files: ['app.js'] }).success).toBe(false);
    const invalid = await call('propose_remediation', { ...input, files: ['app.js'] });
    expect(invalid.body.error).toBe('INVALID_INPUT');
    const proposal = await call('propose_remediation', input);
    expect(proposal.error).toBe(false);
    expect(proposal.body.proposalId).toBeDefined();
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const unauthorized = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId });
    expect(unauthorized.body.error).toBe('AUTHORIZATION_REQUIRED');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const authorization = { projectRoot: root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true };
    const dryRun = await call('remediate_finding', { projectRoot: root, finding: { id: finding.id, file: 'app.js', approval: 'explicitly_approved' }, authorization, strategy: { kind: 'replace', content: repaired }, dryRun: true });
    expect(dryRun.body.remediationStatus).toBe('dry_run');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const foreign = await call('apply_remediation', { projectRoot: otherRoot, remediationId: proposal.body.proposalId, authorization: { ...authorization, projectRoot: otherRoot } });
    expect(foreign.body.error).toBe('PATH_OUTSIDE_ROOT');
    const applied = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization });
    expect(applied.body.status).toBe('applied_pending_verification');
    expect(sha(fs.readFileSync(target))).toBe(sha(repaired));
    expect(fs.readFileSync(target, 'utf8')).toBe(repaired);
    expect(sha(fs.readFileSync(packagePath))).toBe(packageHash);
    const postScan = await call('scan_project', { projectRoot: root });
    expect(postScan.body.findings.some((item: any) => item.ruleId === 'CS-NODE-009')).toBe(false);
    const verified = await call('verify_remediation', { projectRoot: root, remediationId: proposal.body.proposalId });
    expect(verified.error).toBe(false);
    expect(verified.body.status).toBe('verification_inconclusive');
    expect(verified.body.verification.staticFindingPresent).toBe(false);
    expect(sha(fs.readFileSync(target))).toBe(sha(repaired));
    const rollback = await call('rollback_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization });
    expect(rollback.body.status).toBe('rolled_back');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    expect(sha(fs.readFileSync(packagePath))).toBe(packageHash);
  }, 60_000);
});
