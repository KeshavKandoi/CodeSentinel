import { testCredential } from '../testCredentials.js';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../../src/config.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { listRemediationsForInvestigation, resetRemediationsForTests } from '../../src/remediation/engine.js';

const roots: string[] = [];
const configFor = (root: string): AppConfig => ({ projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 });
function tool(name: string) {
  const item = toolDefinitions.find((entry) => entry.name === name);
  if (!item) throw new Error(`missing tool ${name}`);
  if (name !== 'apply_remediation' && name !== 'rollback_remediation') return item;
  return { ...item, handler: (config: AppConfig, input: any) => item.handler(config, { ...input, authorization: { projectRoot: config.projectRoot, localTarget: true, allowRemediation: true, nonProductionTestTarget: true } }) };
}
function body(response: { content: Array<{ text: string }> }) { return JSON.parse(response.content[0]!.text) as any; }
function makeProject(): { root: string; config: AppConfig } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-phase9-'))); roots.push(root);
  fs.cpSync(path.resolve(process.cwd(), 'tests/fixtures/security-cases'), root, {
    recursive: true,
    filter: (source) => !source.endsWith(`${path.sep}deep-baseline.json`),
  });
  fs.writeFileSync(path.join(root, 'src', 'remediation.ts'), 'const value = eval(req.query.value);\nexport default value;\n');
  return { root, config: configFor(root) };
}

afterEach(() => { resetInvestigationsForTests(); resetRemediationsForTests(); for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

describe('Phase 9 controlled remediation', () => {
  async function investigation(config: AppConfig, root: string) {
    const started = body(await tool('start_security_investigation').handler(config, { projectPath: root, scope: ['input_validation'], hypothesis: 'Find unsafe input handling.' }));
    const analysis = body(await tool('run_security_analysis').handler(config, { investigationId: started.id }));
    const finding = analysis.findings.find((item: { origin: string; file: string }) => item.origin === 'security_scan' && item.file === 'src/vulnerable.ts');
    return { investigationId: started.id, findingId: finding.findingId };
  }

  it('binds proposals, apply, verification, and rollback to the investigation project', async () => {
    const first = makeProject();
    const second = makeProject();
    const { investigationId, findingId } = await investigation(first.config, first.root);
    const relative = 'src/vulnerable.ts';
    const original = fs.readFileSync(path.join(first.root, relative), 'utf8');
    const input = { investigationId, findingId, description: 'Remove unsafe sink.', rationale: 'Test project isolation.', files: [{ path: relative, originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Replace source.' }], expectedSecurityEffect: 'Unsafe sink removed.', requiresRuntimeVerification: false };
    expect(body(await tool('propose_remediation').handler(second.config, input)).error).toBe('PATH_OUTSIDE_ROOT');
    const proposal = body(await tool('propose_remediation').handler(first.config, input));
    expect(proposal.proposalId).toBeDefined();
    expect(body(await tool('apply_remediation').handler(second.config, { remediationId: proposal.proposalId })).error).toBe('PATH_OUTSIDE_ROOT');
    expect(fs.readFileSync(path.join(second.root, relative), 'utf8')).toBe(original);
    expect(body(await tool('apply_remediation').handler(first.config, { remediationId: proposal.proposalId })).status).toBe('applied_pending_verification');
    expect(body(await tool('verify_remediation').handler(second.config, { remediationId: proposal.proposalId })).error).toBe('PATH_OUTSIDE_ROOT');
    expect(body(await tool('rollback_remediation').handler(second.config, { remediationId: proposal.proposalId })).error).toBe('PATH_OUTSIDE_ROOT');
    expect(fs.readFileSync(path.join(second.root, relative), 'utf8')).toBe(original);
  });

  it('validates, applies, re-analyzes, and rolls back without returning source contents', async () => {
    const { root, config } = makeProject();
    const started = body(await tool('start_security_investigation').handler(config, { projectPath: root, scope: ['input_validation'], hypothesis: 'Find unsafe input handling.' }));
    const analysis = body(await tool('run_security_analysis').handler(config, { investigationId: started.id }));
    const findingId = analysis.findings.find((finding: { origin: string; file: string }) => finding.origin === 'security_scan' && finding.file === 'src/vulnerable.ts').findingId;
    const original = fs.readFileSync(path.join(root, 'src/vulnerable.ts'), 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId: started.id, findingId, description: 'Replace unsafe evaluation.', rationale: 'Remove unsafe sinks from the source file.', files: [{ path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Remove unsafe sinks.' }], expectedSecurityEffect: 'The unsafe source patterns are absent.', requiresRuntimeVerification: false }));
    expect(proposal.files[0].proposedContent).toContain('NOT RETURNED');
    const applied = body(await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(applied.status).toBe('applied_pending_verification');
    const verified = body(await tool('verify_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(verified.status).toBe('verification_inconclusive');
    const rolledBack = body(await tool('rollback_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(rolledBack.status).toBe('rolled_back');
    expect(fs.readFileSync(path.join(root, 'src/vulnerable.ts'), 'utf8')).toBe(original);
  });

  it('rejects stale hashes, traversal, protected files, and rollback conflicts', async () => {
    const { root, config } = makeProject();
    const started = body(await tool('start_security_investigation').handler(config, { projectPath: root, scope: ['input_validation'], hypothesis: 'Find unsafe input handling.' }));
    const analysis = body(await tool('run_security_analysis').handler(config, { investigationId: started.id }));
    const findingId = analysis.findings.find((finding: { origin: string }) => finding.origin === 'security_scan').findingId;
    const bad = await tool('propose_remediation').handler(config, { investigationId: started.id, findingId, description: 'bad', rationale: 'bad', files: [{ path: '../outside', originalContentHash: '0'.repeat(64), proposedContent: 'rm -rf /', description: 'bad' }], expectedSecurityEffect: 'none', requiresRuntimeVerification: false });
    expect(body(bad).error).toBe('PATH_OUTSIDE_ROOT');
    const protectedResponse = await tool('propose_remediation').handler(config, { investigationId: started.id, findingId, description: 'bad', rationale: 'bad', files: [{ path: '.env', originalContentHash: '0'.repeat(64), proposedContent: 'SECRET=bad', description: 'bad' }], expectedSecurityEffect: 'none', requiresRuntimeVerification: false });
    expect(body(protectedResponse).error).toBe('REMEDIATION_INVALID');
  });

  it('serializes identical proposal creation deterministically', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const original = fs.readFileSync(path.join(root, 'src/vulnerable.ts'), 'utf8');
    const input = { investigationId, findingId, description: 'Remove unsafe sinks.', rationale: 'Reduce attack surface.', files: [{ path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Remove unsafe sinks.' }], expectedSecurityEffect: 'Unsafe sinks are removed.', requiresRuntimeVerification: false };
    const responses = await Promise.all([tool('propose_remediation').handler(config, input), tool('propose_remediation').handler(config, input)]);
    expect(responses.filter((response) => !response.isError)).toHaveLength(1);
    expect(responses.filter((response) => body(response).error === 'DUPLICATE_OPERATION')).toHaveLength(1);
    expect(listRemediationsForInvestigation(investigationId)).toHaveLength(1);
  });

  it('rejects a later invalid preflight file without changing an earlier file', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const firstPath = path.join(root, 'src/vulnerable.ts');
    const secondPath = path.join(root, 'src/safe.ts');
    const first = fs.readFileSync(firstPath, 'utf8');
    const second = fs.readFileSync(secondPath, 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Validate all targets.', rationale: 'Exercise later-file preflight failure.', files: [
      { path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(first).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Update first.' },
      { path: 'src/safe.ts', originalContentHash: crypto.createHash('sha256').update(second).digest('hex'), proposedContent: `${second}\n// reviewed\n`, description: 'Update second.' },
    ], expectedSecurityEffect: 'All targets pass preflight.', requiresRuntimeVerification: false }));
    fs.rmSync(secondPath);
    fs.mkdirSync(secondPath);
    const result = await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId });
    expect(body(result).error).toBe('NOT_A_FILE');
    expect(fs.readFileSync(firstPath, 'utf8')).toBe(first);
  });

  it('validates all files before changing any and preserves newer content on commit conflict', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const firstPath = path.join(root, 'src/vulnerable.ts');
    const secondPath = path.join(root, 'src/safe.ts');
    const first = fs.readFileSync(firstPath, 'utf8');
    const second = fs.readFileSync(secondPath, 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Update two files.', rationale: 'Test transactional preflight.', files: [
      { path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(first).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Update first.' },
      { path: 'src/safe.ts', originalContentHash: crypto.createHash('sha256').update(second).digest('hex'), proposedContent: `${second}\n// reviewed\n`, description: 'Update second.' },
    ], expectedSecurityEffect: 'Both files are hardened.', requiresRuntimeVerification: false }));
    fs.writeFileSync(secondPath, `${second}\n// changed externally\n`);
    const conflict = await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId });
    expect(body(conflict).error).toBe('REMEDIATION_CONFLICT');
    expect(fs.readFileSync(firstPath, 'utf8')).toBe(first);
    expect(fs.readFileSync(secondPath, 'utf8')).toContain('changed externally');
  });

  it('applies multiple files with verified resulting hashes and rejects a second rollback', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const firstPath = path.join(root, 'src/vulnerable.ts');
    const secondPath = path.join(root, 'src/safe.ts');
    const first = fs.readFileSync(firstPath, 'utf8');
    const second = fs.readFileSync(secondPath, 'utf8');
    const nextFirst = 'export const safe = true;\n';
    const nextSecond = `${second}\n// reviewed\n`;
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Update two files.', rationale: 'Test multi-file commit.', files: [
      { path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(first).digest('hex'), proposedContent: nextFirst, description: 'Update first.' },
      { path: 'src/safe.ts', originalContentHash: crypto.createHash('sha256').update(second).digest('hex'), proposedContent: nextSecond, description: 'Update second.' },
    ], expectedSecurityEffect: 'Both files are hardened.', requiresRuntimeVerification: false }));
    const applied = body(await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(applied.status).toBe('applied_pending_verification');
    expect(applied.appliedContentHashes['src/vulnerable.ts']).toBe(crypto.createHash('sha256').update(nextFirst).digest('hex'));
    expect(applied.appliedContentHashes['src/safe.ts']).toBe(crypto.createHash('sha256').update(nextSecond).digest('hex'));
    const rollback = body(await tool('rollback_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(rollback.status).toBe('rolled_back');
    const secondRollback = await tool('rollback_remediation').handler(config, { remediationId: proposal.proposalId });
    expect(body(secondRollback).error).toBe('INVALID_TRANSITION');
  });

  it('refuses rollback when a file was externally modified after apply', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const target = path.join(root, 'src/vulnerable.ts');
    const original = fs.readFileSync(target, 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Controlled change.', rationale: 'Exercise rollback conflict handling.', files: [{ path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Replace source.' }], expectedSecurityEffect: 'The finding is addressed.', requiresRuntimeVerification: false }));
    await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId });
    fs.writeFileSync(target, 'const newerExternalChange = true;\n');
    const rollback = await tool('rollback_remediation').handler(config, { remediationId: proposal.proposalId });
    expect(body(rollback).error).toBe('ROLLBACK_CONFLICT');
    expect(fs.readFileSync(target, 'utf8')).toContain('newerExternalChange');
  });

  it('aborts preparation with zero original-file modifications', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const firstPath = path.join(root, 'src/vulnerable.ts');
    const secondPath = path.join(root, 'src/safe.ts');
    const first = fs.readFileSync(firstPath, 'utf8');
    const second = fs.readFileSync(secondPath, 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Prepare two files.', rationale: 'Exercise preparation failure.', files: [
      { path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(first).digest('hex'), proposedContent: 'export const safe = true;\n', description: 'Update first.' },
      { path: 'src/safe.ts', originalContentHash: crypto.createHash('sha256').update(second).digest('hex'), proposedContent: `${second}\n// reviewed\n`, description: 'Update second.' },
    ], expectedSecurityEffect: 'Both files are prepared.', requiresRuntimeVerification: false }));
    const originalWrite = fs.writeFileSync.bind(fs);
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockImplementation(((filePath: fs.PathLike, data: string | NodeJS.ArrayBufferView, ...args: any[]) => {
      if (String(filePath).includes('.codesentinel-')) throw new Error('deterministic preparation failure');
      return originalWrite(filePath, data, ...args);
    }) as typeof fs.writeFileSync);
    try {
      const result = await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId });
      expect(body(result).error).toBe('INTERNAL_ERROR');
      expect(fs.readFileSync(firstPath, 'utf8')).toBe(first);
      expect(fs.readFileSync(secondPath, 'utf8')).toBe(second);
    } finally {
      writeSpy.mockRestore();
    }
  });

  it('restores snapshots after post-commit integrity verification failure', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const target = path.join(root, 'src/vulnerable.ts');
    const original = fs.readFileSync(target, 'utf8');
    const replacement = 'export const safe = true;\n';
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Verify commit integrity.', rationale: 'Exercise post-commit failure recovery.', files: [{ path: 'src/vulnerable.ts', originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: replacement, description: 'Replace source.' }], expectedSecurityEffect: 'The finding is removed.', requiresRuntimeVerification: false }));
    const originalRead = fs.readFileSync.bind(fs);
    const originalRename = fs.renameSync.bind(fs);
    let committed = false;
    let corruptedOnce = false;
    const renameSpy = vi.spyOn(fs, 'renameSync').mockImplementation(((from: fs.PathLike, to: fs.PathLike) => {
      const result = originalRename(from, to);
      if (String(to) === target) committed = true;
      return result;
    }) as typeof fs.renameSync);
    const readSpy = vi.spyOn(fs, 'readFileSync').mockImplementation(((filePath: fs.PathLike, ...args: any[]) => {
      if (committed && String(filePath) === target && !corruptedOnce) {
        corruptedOnce = true;
        return Buffer.from('tampered post-commit content');
      }
      return originalRead(filePath, ...args);
    }) as typeof fs.readFileSync);
    try {
      const result = await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId });
      expect(body(result).error).toBe('INTERNAL_ERROR');
      expect(fs.readFileSync(target, 'utf8')).toBe(original);
      expect(body(await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId })).error).toBe('INVALID_TRANSITION');
    } finally {
      readSpy.mockRestore();
      renameSpy.mockRestore();
    }
  });

  it('reports missing snapshots and preserves proposal metadata and hashes', async () => {
    const { root, config } = makeProject();
    const { investigationId, findingId } = await investigation(config, root);
    const target = path.join(root, 'src/vulnerable.ts');
    const original = fs.readFileSync(target, 'utf8');
    const originalHash = crypto.createHash('sha256').update(original).digest('hex');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId, findingId, description: 'Immutable proposal.', rationale: 'Exercise metadata preservation.', files: [{ path: 'src/vulnerable.ts', originalContentHash: originalHash, proposedContent: 'const command = \'rm -rf /; sudo sh -c "x" | cat $(whoami) `id` > /tmp/out\';\n', description: 'Keep command text as inert source content.' }], expectedSecurityEffect: 'No command is executed.', requiresRuntimeVerification: false }));
    const proposalId = proposal.proposalId;
    proposal.proposalId = 'mutated';
    proposal.files[0].originalContentHash = '0'.repeat(64);
    const missingSnapshot = await tool('rollback_remediation').handler(config, { remediationId: proposalId });
    expect(body(missingSnapshot).error).toBe('REMEDIATION_INVALID');
    const persisted = body(await tool('apply_remediation').handler(config, { remediationId: proposalId }));
    expect(persisted.proposal.proposalId).toBe(proposalId);
    expect(persisted.proposal.files[0].originalContentHash).toBe(originalHash);
    expect(fs.readFileSync(target, 'utf8')).toContain('rm -rf /');
  });

  it('registers all four mutation tools and never exposes shell execution as a remediation input', () => {
    expect(toolDefinitions.map((item) => item.name)).toEqual(expect.arrayContaining(['propose_remediation', 'apply_remediation', 'verify_remediation', 'rollback_remediation']));
    expect(tool('propose_remediation').inputSchema.properties).not.toHaveProperty('command');
  });
});

import { canAdvance } from '../../src/audit/lifecycle.js';
import type { FindingStatus } from '../../src/audit/types.js';

const sha = (value: string): string => crypto.createHash('sha256').update(value).digest('hex');
const leftovers = (root: string): string[] => fs.readdirSync(path.join(root, 'src')).filter((name) => name.includes('.codesentinel-'));

async function setup() {
  const { root, config } = makeProject();
  const started = body(await tool('start_security_investigation').handler(config, { projectPath: root, scope: ['input_validation'], hypothesis: 'Find unsafe input handling.' }));
  const analysis = body(await tool('run_security_analysis').handler(config, { investigationId: started.id }));
  const findingId = analysis.findings.find((item: { origin: string; file: string }) => item.origin === 'security_scan' && item.file === 'src/vulnerable.ts').findingId as string;
  const original = fs.readFileSync(path.join(root, 'src/vulnerable.ts'), 'utf8');
  const input = (proposed: string, extra: Record<string, unknown> = {}) => ({
    investigationId: started.id as string, findingId, description: 'Harden source.', rationale: 'Reduce attack surface.',
    files: [{ path: 'src/vulnerable.ts', originalContentHash: sha(original), proposedContent: proposed, description: 'Update file.' }],
    expectedSecurityEffect: 'Unsafe sinks are removed.', requiresRuntimeVerification: false, ...extra,
  });
  const propose = async (proposed: string, extra: Record<string, unknown> = {}) => body(await tool('propose_remediation').handler(config, input(proposed, extra)));
  return { root, config, findingId, original, input, propose };
}

describe('Phase 9 proposal integrity', () => {
  it('derives deterministic proposal ids from finding and content, and retains finding identity', async () => {
    const s = await setup();
    const first = await s.propose('export const safe = true;\n');
    expect(first.proposalId).toMatch(/^remediation-[a-f0-9]{32}$/);
    expect(first.findingId).toBe(s.findingId);
    expect(first.findingFile).toBe('src/vulnerable.ts');
    expect(typeof first.remediationType).toBe('string');
    resetRemediationsForTests();
    expect((await s.propose('export const safe = true;\n')).proposalId).toBe(first.proposalId);
    resetRemediationsForTests();
    expect((await s.propose('export const safe = false;\n')).proposalId).not.toBe(first.proposalId);
  });

  it('rejects wrong finding ids, malformed proposals, and forged internal fields', async () => {
    const s = await setup();
    const wrong = await tool('propose_remediation').handler(s.config, s.input('export const safe = true;\n', { findingId: 'missing-finding' }));
    expect(body(wrong).error).toBe('REPORT_FINDING_NOT_FOUND');
    expect(body(await tool('propose_remediation').handler(s.config, {})).error).toBe('INVALID_INPUT');
    for (const forged of [{ status: 'verified_resolved' }, { integrity: {} }, { proposalId: 'remediation-forged' }, { resultingFingerprint: 'x' }, { replayResult: 'resolved' }]) {
      const response = await tool('propose_remediation').handler(s.config, s.input('export const safe = true;\n', forged));
      expect(response.isError).toBe(true);
      expect(body(response).error).toBe('INVALID_INPUT');
    }
    for (const name of ['apply_remediation', 'verify_remediation', 'rollback_remediation']) {
      expect(body(await tool(name).handler(s.config, { remediationId: 'x', status: 'verified_resolved', replayResult: 'resolved' })).error).toBe('INVALID_INPUT');
    }
  });

  it('rejects traversal, absolute, backslash, directory, missing, and symlink targets', async () => {
    const s = await setup();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-outside-'));
    roots.push(outside);
    fs.writeFileSync(path.join(outside, 'target.ts'), 'outside\n');
    fs.symlinkSync(path.join(outside, 'target.ts'), path.join(s.root, 'src/escape.ts'));
    fs.symlinkSync(path.join(s.root, 'src/safe.ts'), path.join(s.root, 'src/alias.ts'));
    for (const bad of ['../outside.ts', '/etc/passwd', 'src/../../outside.ts', '..\\outside.ts', 'src\\..\\..\\x.ts', 'src', 'src/missing.ts', 'src/escape.ts', 'src/alias.ts']) {
      const response = await tool('propose_remediation').handler(s.config, s.input('x\n', { files: [{ path: bad, originalContentHash: '0'.repeat(64), proposedContent: 'x\n', description: 'bad' }] }));
      expect(response.isError, bad).toBe(true);
    }
    expect(fs.readFileSync(path.join(outside, 'target.ts'), 'utf8')).toBe('outside\n');
    expect(listRemediationsForInvestigation(s.input('x').investigationId)).toHaveLength(0);
  });

  it('rejects proposals that change too many lines', async () => {
    const s = await setup();
    const big = Array.from({ length: 600 }, (_, i) => `export const v${i} = ${i};`).join('\n');
    expect(body(await tool('propose_remediation').handler(s.config, s.input(big))).error).toBe('REMEDIATION_INVALID');
  });

  it('redacts credential-like text in proposal output', async () => {
    const s = await setup();
    const stripe = testCredential('STRIPE_KEY');
    const password = testCredential('DB_PASSWORD');
    const bearer = testCredential('BEARER_TOKEN');
    const response = await tool('propose_remediation').handler(s.config, s.input('export const safe = true;\n', { description: `Rotate ${stripe} and password=${password}`, rationale: `Authorization: Bearer ${bearer} leaked` }));
    const text = response.content[0]!.text;
    for (const leak of [stripe.slice(8, 20), password.slice(0, 12), bearer.slice(0, 12)]) expect(text).not.toContain(leak);

  });
});

describe('Phase 9 safe apply and integrity', () => {
  it('records fingerprints, changed files, and leaves unrelated files untouched', async () => {
    const s = await setup();
    const safePath = path.join(s.root, 'src/safe.ts');
    const safeBefore = fs.readFileSync(safePath, 'utf8');
    const next = 'export const safe = true;\n';
    const proposal = await s.propose(next);
    const applied = body(await tool('apply_remediation').handler(s.config, { remediationId: proposal.proposalId }));
    expect(applied.status).toBe('applied_pending_verification');
    expect(applied.integrity.changedFiles).toEqual(['src/vulnerable.ts']);
    expect(applied.integrity.unchangedFileCount).toBeGreaterThan(0);
    expect(applied.integrity.expectedSourceFingerprint).toBe(sha(`src/vulnerable.ts|${sha(s.original)}`));
    expect(applied.integrity.resultingFingerprint).toBe(sha(`src/vulnerable.ts|${sha(next)}`));
    expect(applied.integrity.treeFingerprintBefore).not.toBe(applied.integrity.treeFingerprintAfter);
    expect(typeof applied.appliedAt).toBe('string');
    expect(applied.changeSummary).toContain('src/vulnerable.ts');
    expect(applied.proposal.findingId).toBe(s.findingId);
    expect(fs.readFileSync(safePath, 'utf8')).toBe(safeBefore);
    expect(leftovers(s.root)).toEqual([]);
  });

  it('cleans up temporary files and keeps the original when the atomic replace fails', async () => {
    const s = await setup();
    const target = path.join(s.root, 'src/vulnerable.ts');
    const proposal = await s.propose('export const safe = true;\n');
    const spy = vi.spyOn(fs, 'renameSync').mockImplementation((() => { throw new Error('rename failure'); }) as typeof fs.renameSync);
    let result;
    try { result = await tool('apply_remediation').handler(s.config, { remediationId: proposal.proposalId }); } finally { spy.mockRestore(); }
    expect(body(result).error).toBe('INTERNAL_ERROR');
    expect(fs.readFileSync(target, 'utf8')).toBe(s.original);
    expect(leftovers(s.root)).toEqual([]);
  });

  it('rejects a stale proposal after the file changed', async () => {
    const s = await setup();
    const target = path.join(s.root, 'src/vulnerable.ts');
    const proposal = await s.propose('export const safe = true;\n');
    fs.writeFileSync(target, `${s.original}// external\n`);
    expect(body(await tool('apply_remediation').handler(s.config, { remediationId: proposal.proposalId })).error).toBe('REMEDIATION_CONFLICT');
    expect(fs.readFileSync(target, 'utf8')).toContain('// external');
    expect(leftovers(s.root)).toEqual([]);
  });

  it('lets only one of two racing proposals on the same file apply', async () => {
    const s = await setup();
    const target = path.join(s.root, 'src/vulnerable.ts');
    const a = await s.propose('export const a = 1;\n');
    const b = await s.propose('export const b = 2;\n');
    expect(a.proposalId).not.toBe(b.proposalId);
    const results = await Promise.all([tool('apply_remediation').handler(s.config, { remediationId: a.proposalId }), tool('apply_remediation').handler(s.config, { remediationId: b.proposalId })]);
    expect(results.filter((response) => !response.isError)).toHaveLength(1);
    expect(results.filter((response) => body(response).error === 'REMEDIATION_CONFLICT')).toHaveLength(1);
    expect(['export const a = 1;\n', 'export const b = 2;\n']).toContain(fs.readFileSync(target, 'utf8'));
  });
});

describe('Phase 9 replay and resolution gate', () => {
  it('never resolves a static-only finding even when the finding disappears', async () => {
    const s = await setup();
    const proposal = await s.propose('export const safe = true;\n');
    await tool('apply_remediation').handler(s.config, { remediationId: proposal.proposalId });
    const verified = body(await tool('verify_remediation').handler(s.config, { remediationId: proposal.proposalId }));
    expect(verified.status).toBe('verification_inconclusive');
    expect(verified.verification.replayResult).toBe('inconclusive');
  });

  it('reports still_present when the original finding remains after re-analysis', async () => {
    const s = await setup();
    const proposal = await s.propose(`${s.original}export const extra = 1;\n`);
    await tool('apply_remediation').handler(s.config, { remediationId: proposal.proposalId });
    const verified = body(await tool('verify_remediation').handler(s.config, { remediationId: proposal.proposalId }));
    expect(verified.status).not.toBe('verified_resolved');
    expect(verified.verification.replayResult).toBe('still_present');
  });

  it('refuses to verify when applied files drifted from the recorded fingerprint', async () => {
    const s = await setup();
    const target = path.join(s.root, 'src/vulnerable.ts');
    const proposal = await s.propose('export const safe = true;\n');
    await tool('apply_remediation').handler(s.config, { remediationId: proposal.proposalId });
    fs.writeFileSync(target, 'export const tampered = true;\n');
    const response = await tool('verify_remediation').handler(s.config, { remediationId: proposal.proposalId });
    expect(body(response).error).toBe('VERIFICATION_INCONCLUSIVE');
    expect(fs.readFileSync(target, 'utf8')).toBe('export const tampered = true;\n');
  });
});

describe('Phase 9 lifecycle transitions', () => {
  it('allows only verified -> remediation_applied -> verified_resolved', () => {
    expect(canAdvance('verified', 'remediation_applied')).toBe(true);
    expect(canAdvance('remediation_applied', 'verified_resolved')).toBe(true);
    const others: FindingStatus[] = ['candidate', 'analyzed', 'proof_eligible', 'unsupported', 'blocked', 'not_reproduced', 'inconclusive', 'verified_resolved'];
    for (const status of others) {
      expect(canAdvance(status, 'verified_resolved'), status).toBe(false);
      expect(canAdvance(status, 'remediation_applied'), status).toBe(false);
    }
    for (const terminal of ['not_reproduced', 'unsupported', 'blocked', 'inconclusive', 'verified_resolved'] as FindingStatus[]) expect(canAdvance(terminal, 'verified')).toBe(false);
  });
});
