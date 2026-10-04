import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeAll, afterAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from '../../src/config.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { linkSecurityReceiptToRemediation, listSecurityReceiptsForFinding, proveSecurityFinding, replaySecurityProof, resetSecurityProofsForTests } from '../../src/proof/engine.js';
import { resetInvestigationsForTests } from '../../src/investigation/orchestrator.js';
import { resetRemediationsForTests } from '../../src/remediation/engine.js';

const vulnerableFixture = fs.realpathSync(fileURLToPath(new URL('../fixtures/proof-runtime/vulnerable', import.meta.url)));
const secureSource = fs.readFileSync(fileURLToPath(new URL('../fixtures/proof-runtime/secure/src/app.ts', import.meta.url)), 'utf8');
const roots: string[] = [];
let server: http.Server;
let origin = '';
let secureOracle = false;
let replayMode: 'normal' | 'redirect' | 'timeout' | 'large' = 'normal';

function tool(name: string) {
  const found = toolDefinitions.find((item) => item.name === name);
  if (!found) throw new Error(`Missing tool ${name}`);
  return found;
}

function body(response: { content: Array<{ text: string }> }): any { return JSON.parse(response.content[0]!.text); }

beforeAll(async () => {
  server = http.createServer((_request, response) => {
    if (replayMode === 'redirect') {
      response.writeHead(302, { location: '/newly-introduced-route' });
      response.end();
      return;
    }
    if (replayMode === 'timeout') {
      setTimeout(() => response.end('late response'), 100);
      return;
    }
    if (replayMode === 'large') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('x'.repeat(100_000));
      return;
    }
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
  replayMode = 'normal';
  secureOracle = false;
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
    expect(proof.data.replayContract).toMatchObject({
      proofType: 'sql_injection', method: 'GET', relativeRoute: '/search', parameterName: 'query',
      inertProbeValue: 'codesentinel-inert-probe',
      targetConstraints: { allowedOrigin: origin, maxRedirects: 0 },
      sessionLabelReferences: [], oracleDefinition: { kind: 'body_contains', safeResult: 'not_reproduced' },
    });
    expect(JSON.stringify(proof.data)).not.toContain('select ');
    const callerContract = proof.data.replayContract!;
    callerContract.relativeRoute = '/caller-tampered';
    expect(listSecurityReceiptsForFinding(finding.findingId).find((receipt) => receipt.receiptId === proof.data.receiptId)?.replayContract?.relativeRoute).toBe('/search');
    callerContract.relativeRoute = '/search';

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
    const replay = receipts.find((receipt) => receipt.receiptId === verified.verification.runtimeReceiptId);
    expect(replay?.remediationRef).toBe(proposal.proposalId);
    expect(replay?.replayOfReceiptId).toBe(proof.data.receiptId);
    expect(replay?.beforeAfter).toEqual({ beforeStatus: 'verified', afterStatus: 'not_reproduced' });
  });

  it('does not resolve a remediation when static analysis disappears but replay remains vulnerable', async () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-proof-still-vulnerable-')));
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
    const targetPath = path.join(root, 'src/app.ts');
    const original = fs.readFileSync(targetPath, 'utf8');
    const proposal = body(await tool('propose_remediation').handler(config, { investigationId: started.id, findingId: finding.findingId, description: 'Remove static sink only.', rationale: 'Exercise replay guard.', files: [{ path: 'src/app.ts', originalContentHash: crypto.createHash('sha256').update(original).digest('hex'), proposedContent: secureSource, description: 'Remove the static sink.' }], expectedSecurityEffect: 'The static finding disappears.', requiresRuntimeVerification: true, runtimeVerification: { findingId: finding.findingId, target: { allowedOrigin: origin, minRequestIntervalMs: 0 }, sessions: [], sessionParams: {} } }));
    body(await tool('apply_remediation').handler(config, { remediationId: proposal.proposalId }));
    secureOracle = false;
    const result = body(await tool('verify_remediation').handler(config, { remediationId: proposal.proposalId }));
    expect(result.status).toBe('verification_inconclusive');
    expect(result.verification.runtimeStatus).toBe('verified');
  });

  it('rejects replay when receipt, target, route, method, or probe contract does not match', async () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-proof-contract-')));
    roots.push(root);
    fs.cpSync(vulnerableFixture, root, { recursive: true });
    const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2 };
    const scan = body(await tool('scan_project').handler(config, {}));
    const finding = scan.findings.find((item: { category: string }) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    const proof = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: origin, minRequestIntervalMs: 0 } });
    expect(proof.ok).toBe(true);
    if (!proof.ok) return;
    const base = { findingId: finding.id, target: { allowedOrigin: origin, minRequestIntervalMs: 0 }, sessions: [], sessionParams: {} };
    expect(linkSecurityReceiptToRemediation(finding.id, proof.data.receiptId, 'remediation-contract-test').ok).toBe(true);
    const altered = (change: (receipt: any) => any) => replaySecurityProof(config, base, change({ ...proof.data, replayContract: { ...(proof.data.replayContract ?? {}) } }), 'remediation-contract-test');
    expect((await altered((receipt) => ({ ...receipt, replayContract: { ...receipt.replayContract, relativeRoute: '/changed' } }))).ok).toBe(false);
    expect((await altered((receipt) => ({ ...receipt, replayContract: { ...receipt.replayContract, method: 'POST' } }))).ok).toBe(false);
    expect((await altered((receipt) => ({ ...receipt, replayContract: { ...receipt.replayContract, inertProbeValue: 'changed-probe' } }))).ok).toBe(false);
    const mismatch = await replaySecurityProof(config, { ...base, target: { allowedOrigin: `${origin}-different`, minRequestIntervalMs: 0 } }, proof.data, 'remediation-target-test');
    expect(mismatch.ok).toBe(false);
    const secure = await proveSecurityFinding(config, { findingId: finding.id, target: { allowedOrigin: origin, maxResponseBytes: 1, minRequestIntervalMs: 0 } });
    expect(secure.ok).toBe(true);
    expect((await replaySecurityProof(config, base, { ...proof.data, receiptId: 'missing-receipt' }, 'remediation-missing-receipt')).ok).toBe(false);
    expect((await replaySecurityProof(config, base, { ...proof.data, status: 'not_reproduced' }, 'remediation-nonverified')).ok).toBe(false);
  });

  it('blocks replay on a newly introduced redirect, timeout, or response-size violation', async () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-proof-controls-')));
    roots.push(root);
    fs.cpSync(vulnerableFixture, root, { recursive: true });
    const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2 };
    const scan = body(await tool('scan_project').handler(config, {}));
    const finding = scan.findings.find((item: { category: string }) => item.category === 'injection');
    expect(finding).toBeDefined();
    if (!finding) return;
    const cases = [
      { mode: 'redirect' as const, target: { allowedOrigin: origin, minRequestIntervalMs: 0 } },
      { mode: 'timeout' as const, target: { allowedOrigin: origin, requestTimeoutMs: 10, minRequestIntervalMs: 0 } },
      { mode: 'large' as const, target: { allowedOrigin: origin, maxResponseBytes: 128, minRequestIntervalMs: 0 } },
    ];
    for (const item of cases) {
      replayMode = 'normal';
      const proof = await proveSecurityFinding(config, { findingId: finding.id, target: item.target });
      expect(proof.ok).toBe(true);
      if (!proof.ok) return;
      const linked = linkSecurityReceiptToRemediation(finding.id, proof.data.receiptId, `remediation-${item.mode}`);
      expect(linked.ok).toBe(true);
      if (!linked.ok) return;
      replayMode = item.mode;
      const replay = await replaySecurityProof(config, { findingId: finding.id, target: item.target, sessions: [], sessionParams: {} }, linked.data, `remediation-${item.mode}`);
      expect(replay.ok).toBe(true);
      if (replay.ok) expect(replay.data.status).toBe('blocked');
      resetSecurityProofsForTests();
    }
  });
});

async function prepareAppliedRemediation() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-phase9-')));
  roots.push(root);
  fs.cpSync(vulnerableFixture, root, { recursive: true });
  const config: AppConfig = { projectRoot: root, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 };
  const started = body(await tool('start_security_investigation').handler(config, { projectPath: root, scope: ['input_validation'], hypothesis: 'Phase 9 verification hardening.' }));
  const analyzed = body(await tool('run_security_analysis').handler(config, { investigationId: started.id }));
  const finding = analyzed.findings.find((item: { origin: string; category: string }) => item.origin === 'security_scan' && item.category === 'injection');
  const proof = await proveSecurityFinding(config, { findingId: finding.findingId, target: { allowedOrigin: origin, minRequestIntervalMs: 0 } });
  if (!proof.ok) throw new Error('proof failed');
  const original = fs.readFileSync(path.join(root, 'src/app.ts'), 'utf8');
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
  if (applied.status !== 'applied_pending_verification') throw new Error('apply failed');
  return { config, findingId: finding.findingId as string, remediationId: proposal.proposalId as string, proof: proof.data };
}

describe('Phase 9 remediation verification hardening', () => {
  it('never leaves a remediation stuck in verifying after a blocked or failed verification', async () => {
    const { config, remediationId } = await prepareAppliedRemediation();
    replayMode = 'redirect';
    await tool('verify_remediation').handler(config, { remediationId });
    const { getRemediation } = await import('../../src/remediation/engine.js');
    const record = getRemediation(remediationId);
    expect(record.ok).toBe(true);
    if (!record.ok) return;
    expect(['verification_inconclusive', 'verification_blocked', 'still_vulnerable', 'changed_finding']).toContain(record.data.status);
    expect(record.data.status).not.toBe('verifying');
    expect(record.data.status).not.toBe('verified_resolved');
  });

  it('serializes concurrent verifications and ends in a terminal state', async () => {
    const { config, remediationId } = await prepareAppliedRemediation();
    secureOracle = true;
    const [first, second] = await Promise.all([
      tool('verify_remediation').handler(config, { remediationId }),
      tool('verify_remediation').handler(config, { remediationId }),
    ]);
    const { getRemediation } = await import('../../src/remediation/engine.js');
    const record = getRemediation(remediationId);
    expect(record.ok).toBe(true);
    if (!record.ok) return;
    expect(record.data.status).not.toBe('verifying');
    expect([first.isError === true, second.isError === true].filter(Boolean).length).toBeLessThanOrEqual(1);
  });

  it('accepts a receipt only for the origin it was created for', async () => {
    const { isTrustedVerifiedReceipt } = await import('../../src/proof/engine.js');
    const { config, findingId, proof } = await prepareAppliedRemediation();
    expect(proof.targetOrigin).toBe(origin);
    expect(isTrustedVerifiedReceipt(proof, 'sql_injection', origin)).toBe(true);
    expect(isTrustedVerifiedReceipt(proof, 'sql_injection', 'http://127.0.0.1:1')).toBe(false);
    const stored = listSecurityReceiptsForFinding(findingId).find((receipt) => receipt.receiptId === proof.receiptId)!;
    expect(stored.targetOrigin).toBe(origin);
    expect(config.projectRoot.length).toBeGreaterThan(0);
  });

  it('rejects replaying a receipt against a different target origin and stamps replays with their origin', async () => {
    const { config, findingId, proof } = await prepareAppliedRemediation();
    const bound = listSecurityReceiptsForFinding(findingId).find((receipt) => receipt.receiptId === proof.receiptId)!;
    expect(bound.remediationRef).not.toBeNull();
    const remediationRef = bound.remediationRef as string;
    const other = http.createServer((_request, response) => { response.writeHead(200); response.end('safe fixture response'); });
    await new Promise<void>((resolve) => other.listen(0, '127.0.0.1', resolve));
    const address = other.address();
    if (!address || typeof address === 'string') throw new Error('no address');
    const otherOrigin = `http://127.0.0.1:${address.port}`;
    try {
      secureOracle = true;
      const crossed = await replaySecurityProof(config, { findingId, target: { allowedOrigin: otherOrigin, minRequestIntervalMs: 0 }, sessions: [], sessionParams: {} }, bound, remediationRef);
      expect(crossed.ok).toBe(false);
      const same = await replaySecurityProof(config, { findingId, target: { allowedOrigin: origin, minRequestIntervalMs: 0 }, sessions: [], sessionParams: {} }, bound, remediationRef);
      expect(same.ok).toBe(true);
      if (same.ok) expect(same.data.targetOrigin).toBe(origin);
    } finally {
      await new Promise<void>((resolve) => other.close(() => resolve()));
    }
  });
});
