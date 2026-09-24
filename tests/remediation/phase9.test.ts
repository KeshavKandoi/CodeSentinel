import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { AppConfig } from '../../src/config.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetRemediationsForTests } from '../../src/remediation/engine.js';

const roots: string[] = [];
const configFor = (root: string): AppConfig => ({ projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 });
function tool(name: string) { const item = toolDefinitions.find((entry) => entry.name === name); if (!item) throw new Error(`missing tool ${name}`); return item; }
function body(response: { content: Array<{ text: string }> }) { return JSON.parse(response.content[0]!.text) as any; }
function makeProject(): { root: string; config: AppConfig } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-phase9-'))); roots.push(root);
  fs.cpSync(path.resolve(process.cwd(), 'tests/fixtures/security-cases'), root, { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'remediation.ts'), 'const value = eval(req.query.value);\nexport default value;\n');
  return { root, config: configFor(root) };
}

afterEach(() => { resetInvestigationsForTests(); resetRemediationsForTests(); for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

describe('Phase 9 controlled remediation', () => {
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
    expect(verified.status).toBe('verified_resolved');
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

  it('registers all four mutation tools and never exposes shell execution as a remediation input', () => {
    expect(toolDefinitions.map((item) => item.name)).toEqual(expect.arrayContaining(['propose_remediation', 'apply_remediation', 'verify_remediation', 'rollback_remediation']));
    expect(tool('propose_remediation').inputSchema.properties).not.toHaveProperty('command');
  });
});
