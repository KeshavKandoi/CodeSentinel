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
    const nonexistentFinding = await call('propose_remediation', { ...input, findingId: 'missing-rule-finding' });
    expect(nonexistentFinding.body.error).toBe('REPORT_FINDING_NOT_FOUND');
    const proposal = await call('propose_remediation', input);
    expect(proposal.error).toBe(false);
    expect(proposal.body.proposalId).toBeDefined();
    expect(proposal.body).toMatchObject({ findingId: investigationFinding.findingId, projectRoot: root });
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const unauthorized = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId });
    expect(unauthorized.body.error).toBe('AUTHORIZATION_REQUIRED');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const authorization = { projectRoot: root, localTarget: true, allowRemediation: true, nonProductionTestTarget: true };
    const nonexistentProposal = await call('apply_remediation', { projectRoot: root, remediationId: 'remediation-00000000000000000000000000000000', authorization });
    expect(nonexistentProposal.body.error).toBe('REMEDIATION_NOT_FOUND');
    const noncanonical = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization: { ...authorization, projectRoot: `${root}/.` } });
    expect(noncanonical.body.error).toBe('AUTHORIZATION_REJECTED');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    for (const flag of ['localTarget', 'allowRemediation', 'nonProductionTestTarget']) {
      const denied = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization: { ...authorization, [flag]: false } });
      expect(denied.body.error).toBe('AUTHORIZATION_REJECTED');
      expect(sha(fs.readFileSync(target))).toBe(originalHash);
    }
    const dryRun = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization, dryRun: true });
    expect(dryRun.body.remediationStatus).toBe('dry_run');
    expect(dryRun.body.validationStatus).toBe('passed');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    fs.writeFileSync(target, `${vulnerable}\n`);
    const staleHash = sha(fs.readFileSync(target));
    const stale = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization });
    expect(stale.body.error).toBe('REMEDIATION_CONFLICT');
    expect(sha(fs.readFileSync(target))).toBe(staleHash);
    fs.writeFileSync(target, vulnerable);
    const foreign = await call('apply_remediation', { projectRoot: otherRoot, remediationId: proposal.body.proposalId, authorization: { ...authorization, projectRoot: otherRoot } });
    expect(foreign.body.error).toBe('PATH_OUTSIDE_ROOT');
    const applied = await call('apply_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization });
    expect(applied.body).toMatchObject({ remediationStatus: 'validated_pending_retest', validationStatus: 'passed', proposalId: proposal.body.proposalId, remediationId: proposal.body.proposalId });
    expect(sha(fs.readFileSync(target))).toBe(sha(repaired));
    expect(fs.readFileSync(target, 'utf8')).toBe(repaired);
    expect(sha(fs.readFileSync(packagePath))).toBe(packageHash);
    expect(execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()).toBe('M app.js');
    const postScan = await call('scan_project', { projectRoot: root });
    expect(postScan.body.findings.some((item: any) => item.ruleId === 'CS-NODE-009')).toBe(false);
    const retested = await call('retest_finding', { projectRoot: root, findingId: finding.id });
    expect(retested.body).toMatchObject({ result: 'resolved', remediationId: proposal.body.proposalId, proposalId: proposal.body.proposalId });
    const sweep = await call('security_remediation_sweep', { projectRoot: root, remediationIds: [proposal.body.proposalId] });
    expect(sweep.body.findings.resolved.some((item: any) => item.findingId === finding.id)).toBe(true);
    expect(sweep.body.findings.resolved[0]).toMatchObject({ remediationId: proposal.body.proposalId, proposalId: proposal.body.proposalId });
    expect(sweep.body.newFindings).toHaveLength(0);
    expect(sha(fs.readFileSync(target))).toBe(sha(repaired));
    const foreignRollback = await call('rollback_remediation', { projectRoot: otherRoot, remediationId: proposal.body.proposalId, authorization: { ...authorization, projectRoot: otherRoot } });
    expect(foreignRollback.body.error).toBe('PATH_OUTSIDE_ROOT');
    expect(sha(fs.readFileSync(target))).toBe(sha(repaired));
    const rollback = await call('rollback_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization });
    expect(rollback.body.status).toBe('rolled_back');
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const repeated = await call('rollback_remediation', { projectRoot: root, remediationId: proposal.body.proposalId, authorization });
    expect(repeated.body.error).toBe('INVALID_TRANSITION');
    expect(sha(fs.readFileSync(packagePath))).toBe(packageHash);
    const invalidProposal = await call('propose_remediation', { ...input, description: 'Test failed validation rollback.', files: [{ ...input.files[0], proposedContent: `${repaired}const =;\n` }] });
    expect(invalidProposal.error).toBe(false);
    const failedValidation = await call('apply_remediation', { projectRoot: root, remediationId: invalidProposal.body.proposalId, authorization });
    expect(failedValidation.body).toMatchObject({ remediationStatus: 'rolled_back', validationStatus: 'failed', rollbackStatus: 'succeeded' });
    expect(sha(fs.readFileSync(target))).toBe(originalHash);
    const conflictProposal = await call('propose_remediation', { ...input, description: 'Test unexpected post-write change.', files: [{ ...input.files[0], proposedContent: `${repaired}\n` }] });
    expect(conflictProposal.error).toBe(false);
    const conflictApplied = await call('apply_remediation', { projectRoot: root, remediationId: conflictProposal.body.proposalId, authorization });
    expect(conflictApplied.body.remediationStatus).toBe('validated_pending_retest');
    fs.appendFileSync(target, '// separate user change\n');
    const changedByUser = sha(fs.readFileSync(target));
    const driftRetest = await call('retest_finding', { projectRoot: root, findingId: finding.id });
    expect(driftRetest.body).toMatchObject({ result: 'inconclusive', retestStatus: 'failed' });
    expect(sha(fs.readFileSync(target))).toBe(changedByUser);
    const conflictRollback = await call('rollback_remediation', { projectRoot: root, remediationId: conflictProposal.body.proposalId, authorization });
    expect(conflictRollback.body.error).toBe('ROLLBACK_CONFLICT');
    expect(sha(fs.readFileSync(target))).toBe(changedByUser);
  }, 60_000);
});
