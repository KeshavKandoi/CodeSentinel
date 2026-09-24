import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeAll, afterAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { listSecurityReceiptsForFinding, proveSecurityFinding, resetSecurityProofsForTests } from '../../src/proof/engine.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetRemediationsForTests } from '../../src/remediation/engine.js';

const vulnerableFixture = fs.realpathSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable', import.meta.url)));
const secureSource = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/secure/src/app.ts', import.meta.url)), 'utf8');
const roots: string[] = [];
let server: http.Server;
let origin = '';
let secureOracle = false;

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`Missing tool ${name}`);
  return found;
}

function body(response: { content: Array<{ text: string }> }): any { return JSON.parse(response.content[0]!.text); }

beforeAll(async () => {
  server = http.createServer((_request, response) => {
    response.writeHead(secureOracle ? 200 : 200, { 'content-type': 'text/plain' });
    response.end(secureOracle ? 'safe fixture response' : 'CODESENTINEL_PROOF_SQLI_SENTINEL');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Lifecycle fixture did not expose a TCP address.');
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

afterEach(() => {
  resetSecurityProofsForTests();
  resetInvestigationsForTests();
  resetRemediationsForTests();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('proof to remediation lifecycle', () => {
  it('requires semantic proof replay before reporting a source remediation resolved', async () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-proof-lifecycle-')));
    roots.push(root);
    fs.cpSync(vulnerableFixture, root, { recursive: true });
    const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };

    const started = body(await tool('start_security_investigation').handler(config, { projectPath: root, scope: ['input_validation'], hypothesis: 'Prove and remediate the local SQL injection candidate.' }));
    const analyzed = body(await tool('run_security_analysis').handler(config, { investigationId: started.id }));
    const finding = analyzed.findings.find((item: { origin: string; category: string }) => item.origin === 'security_scan' && item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;

    const proof = await proveSecurityFinding(config, { findingId: finding.findingId, target: { allowedOrigin: origin, minRequestIntervalMs: 0 } });
    expect(proof.ok).toBe(true);
    if (!proof.ok) return;
    expect(proof.data.status).toBe('verified');

    const targetPath = path.join(root, 'src/app.ts');
    const original = fs.readFileSync(targetPath, 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, {
      investigationId: started.id,
      findingId: finding.findingId,
      description: 'Replace the unsafe query handler with the secure fixture implementation.',
      rationale: 'Use a parameterized query and preserve the route functionality.',
      files: [{ path: 'src/app.ts', originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: secureSource, description: 'Apply the bounded secure fixture implementation.' }],
      expectedSecurityEffect: 'The SQL injection candidate disappears and the proof marker is no longer returned.',
      requiresRuntimeVerification: true,
      runtimeVerification: { findingId: finding.findingId, target: { allowedOrigin: origin, minRequestIntervalMs: 0 }, sessions: [], sessionParams: {} },
    }));
    const applied = body(await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(applied.status).toBe('applied_pending_verification');

    secureOracle = true;
    const verified = body(await tool('verify_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(verified.status).toBe('verified_resolved');
    expect(verified.verification.runtimeStatus).toBe('not_reproduced');
    expect(verified.verification.runtimeReceiptId).toBeTruthy();

    const receipts = listSecurityReceiptsForFinding(finding.findingId);
    const originalReceipt = receipts.find((receipt) => receipt.receiptId === proof.data.receiptId);
    expect(originalReceipt?.reVerification.status).toBe('not_reproduced');
    expect(originalReceipt?.reVerification.receiptId).toBe(verified.verification.runtimeReceiptId);
    expect(receipts.find((receipt) => receipt.receiptId === verified.verification.runtimeReceiptId)?.remediationRef).toBe(proposal.proposalId);
  });
});
