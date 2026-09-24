import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { AppConfig } from '../config.js';
import { resolveExistingWithinRoot, resolveWithinRoot } from '../fs/pathGuard.js';
import { err, ok, type ToolOutcome } from '../types.js';
import { detachedRedacted } from '../report/redaction.js';
import { getInvestigation, runSecurityAnalysis, startInvestigation } from '../investigation/orchestrator.js';
import type { InvestigationFinding, SecurityInvestigation } from '../investigation/types.js';
import type { ProposeRemediationInput } from '../validation/schemas.js';
import type { RemediationFileChange, RemediationLifecycle, RemediationProposal, RemediationRecord, RemediationVerification } from './types.js';
import { verifyFinding } from '../runtime/engine.js';
import { listSecurityReceiptsForFinding, replaySecurityProof } from '../proof/engine.js';

const MAX_FILE_BYTES = 1_000_000;
const MAX_TOTAL_BYTES = 2_000_000;
const MAX_RECORDS = 100;
const records = new Map<string, RemediationRecord>();
const locks = new Map<string, Promise<void>>();
const FORBIDDEN = /(^|\/)(\.env(?:\..*)?|\.ssh|credentials?|id_rsa|.*\.(?:pem|key|p12|pfx))$/i;

function sha256(content: string | Buffer): string { return crypto.createHash('sha256').update(content).digest('hex'); }
function now(): string { return new Date().toISOString(); }
function newId(): string { return `remediation-${crypto.randomUUID()}`; }
function lockKey(record: RemediationRecord): string { return `${record.proposal.investigationId}:${record.proposal.files.map((f) => f.path).sort().join('|')}`; }
function proposalLockKey(input: ProposeRemediationInput): string {
  return `proposal:${input.investigationId}:${input.findingId}:${input.files.map((file) => `${file.path}:${file.originalContentHash}:${sha256(file.proposedContent)}`).sort().join('|')}`;
}
async function withLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => { release = resolve; });
  locks.set(key, current);
  await previous;
  try { return await operation(); } finally { release(); if (locks.get(key) === current) locks.delete(key); }
}

function invalid(message: string): ToolOutcome<never> { return err('REMEDIATION_INVALID', message); }
function findingFor(investigation: SecurityInvestigation, findingId: string): InvestigationFinding | null {
  return investigation.findings.find((finding) => finding.findingId === findingId) ?? null;
}
function validateFile(config: AppConfig, change: RemediationFileChange): ToolOutcome<{ absolute: string; content: string }> {
  if (path.isAbsolute(change.path) || change.path.includes('\\') || change.path.split('/').includes('..')) return err('PATH_OUTSIDE_ROOT', `Remediation path "${change.path}" must be a root-relative path without traversal.`);
  if (FORBIDDEN.test(change.path) || change.path.toLowerCase().startsWith('.git/')) return invalid(`Remediation path "${change.path}" is protected and cannot be modified.`);
  let absolute: string;
  try { absolute = resolveExistingWithinRoot(config.projectRoot, change.path); } catch { return err('PATH_OUTSIDE_ROOT', `Remediation path "${change.path}" is outside the project root.`); }
  let stat: fs.Stats;
  try { stat = fs.lstatSync(absolute); } catch { return err('NOT_FOUND', `Remediation file "${change.path}" was not found.`); }
  if (stat.isSymbolicLink()) return invalid(`Remediation file "${change.path}" is a symbolic link.`);
  if (!stat.isFile()) return err('NOT_A_FILE', `Remediation path "${change.path}" is not a regular file.`);
  if (stat.size > MAX_FILE_BYTES || Buffer.byteLength(change.proposedContent, 'utf8') > MAX_FILE_BYTES) return err('FILE_TOO_LARGE', `Remediation file "${change.path}" exceeds the bounded file size.`);
  const current = fs.readFileSync(absolute);
  if (current.includes(0) || Buffer.from(change.proposedContent).includes(0)) return invalid(`Binary content is not supported for remediation file "${change.path}".`);
  return ok({ absolute, content: current.toString('utf8') });
}
function publicProposal(proposal: RemediationProposal): RemediationProposal {
  return detachedRedacted({ ...proposal, files: proposal.files.map((file) => ({ ...file, proposedContent: '[SOURCE CONTENT NOT RETURNED]' })) });
}
function safeRecord(record: RemediationRecord): RemediationRecord {
  return detachedRedacted({
    ...record,
    proposal: publicProposal(record.proposal),
    snapshots: record.snapshots.map((snapshot) => ({ ...snapshot, originalContent: '[SNAPSHOT CONTENT NOT RETURNED]' })),
  });
}
function currentInvestigation(id: string): ToolOutcome<SecurityInvestigation> { return getInvestigation(id); }

function freezeProposal(proposal: RemediationProposal): RemediationProposal {
  for (const file of proposal.files) Object.freeze(file);
  if (proposal.runtimeVerification) Object.freeze(proposal.runtimeVerification);
  return Object.freeze(proposal);
}

export async function proposeRemediation(config: AppConfig, input: ProposeRemediationInput): Promise<ToolOutcome<RemediationProposal>> {
  return withLock(proposalLockKey(input), async () => {
    const investigationResult = currentInvestigation(input.investigationId);
    if (!investigationResult.ok) return investigationResult;
    const investigation = investigationResult.data;
    const finding = findingFor(investigation, input.findingId);
    if (!finding) return err('REPORT_FINDING_NOT_FOUND', `Finding "${input.findingId}" was not found in investigation "${input.investigationId}".`);
    if (investigation.status !== 'completed' && investigation.status !== 'awaiting_verification') return err('INVESTIGATION_INCOMPLETE', 'Remediation requires a completed or verification-ready investigation.');
    if (input.files.some((file, index) => input.files.findIndex((other) => other.path === file.path) !== index)) return invalid('A remediation proposal cannot contain duplicate file paths.');
    const total = input.files.reduce((sum, file) => sum + Buffer.byteLength(file.proposedContent, 'utf8'), 0);
    if (total > MAX_TOTAL_BYTES) return invalid('The remediation proposal exceeds the total size bound.');
    for (const file of input.files) {
      const checked = validateFile(config, file);
      if (!checked.ok) return checked;
      if (sha256(checked.data.content) !== file.originalContentHash) return err('REMEDIATION_CONFLICT', `Original hash mismatch for "${file.path}"; the proposal is stale.`);
    }
    const duplicate = [...records.values()].find((record) => proposalLockKey(record.proposal as ProposeRemediationInput) === proposalLockKey(input));
    if (duplicate) return err('DUPLICATE_OPERATION', `An identical remediation proposal already exists as "${duplicate.proposal.proposalId}".`);
    if (input.runtimeVerification && input.runtimeVerification.findingId !== input.findingId) return invalid('runtimeVerification.findingId must match findingId.');
    const proposal = freezeProposal({ proposalId: newId(), ...input, files: input.files.map((file) => ({ ...file })), createdAt: now() });
    const record: RemediationRecord = { proposal, status: 'validated', snapshots: [], appliedContentHashes: {}, verification: null, updatedAt: now() };
    if (records.size >= MAX_RECORDS) return err('BUDGET_EXCEEDED', 'The bounded remediation store is full.');
    records.set(proposal.proposalId, record);
    return ok(publicProposal(proposal));
  });
}

export function getRemediation(remediationId: string): ToolOutcome<RemediationRecord> {
  const record = records.get(remediationId);
  return record ? ok(safeRecord(record)) : err('REMEDIATION_NOT_FOUND', `Remediation "${remediationId}" was not found.`);
}
export function listRemediationsForInvestigation(investigationId: string): RemediationRecord[] {
  return [...records.values()].filter((record) => record.proposal.investigationId === investigationId).map(safeRecord);
}

export async function applyRemediation(config: AppConfig, remediationId: string): Promise<ToolOutcome<RemediationRecord>> {
  const existing = records.get(remediationId);
  if (!existing) return err('REMEDIATION_NOT_FOUND', `Remediation "${remediationId}" was not found.`);
  return withLock(lockKey(existing), async () => {
    const record = records.get(remediationId)!;
    if (record.status !== 'validated' && record.status !== 'proposed') return err('INVALID_TRANSITION', `Remediation cannot be applied from status "${record.status}".`);
    const investigation = currentInvestigation(record.proposal.investigationId);
    if (!investigation.ok) return investigation;
    if (!findingFor(investigation.data, record.proposal.findingId)) return err('REPORT_FINDING_NOT_FOUND', `Finding "${record.proposal.findingId}" is no longer present in the authorized investigation.`);
    const checked: Array<{ change: RemediationFileChange; absolute: string; content: string; proposedHash: string; mode: number }> = [];
    // Complete preflight: no mutation is allowed until every target passes.
    for (const change of record.proposal.files) {
      const result = validateFile(config, change); if (!result.ok) return result;
      if (sha256(result.data.content) !== change.originalContentHash) return err('REMEDIATION_CONFLICT', `Original hash mismatch for "${change.path}"; no files were changed.`);
      checked.push({ change, absolute: result.data.absolute, content: result.data.content, proposedHash: sha256(change.proposedContent), mode: fs.statSync(result.data.absolute).mode });
    }
    record.status = 'preparing';
    try {
      record.snapshots = checked.map(({ change, content }) => ({ path: change.path, originalContentHash: change.originalContentHash, originalContent: content, capturedAt: now() }));
      if (record.snapshots.length !== checked.length || record.snapshots.some((snapshot) => sha256(snapshot.originalContent) !== snapshot.originalContentHash)) throw new Error('snapshot verification failed');
    } catch {
      record.status = 'apply_failed'; record.updatedAt = now();
      return err('INTERNAL_ERROR', 'Remediation snapshots could not be created and no files were changed.');
    }
    const prepared: Array<{ target: string; temp: string; expectedHash: string }> = [];
    try {
      for (const item of checked) {
        const temp = `${item.absolute}.codesentinel-${crypto.randomUUID()}.tmp`;
        fs.writeFileSync(temp, item.change.proposedContent, { encoding: 'utf8', mode: item.mode, flag: 'wx' });
        const preparedBytes = fs.readFileSync(temp);
        if (sha256(preparedBytes) !== item.proposedHash) throw new Error('prepared content hash verification failed');
        prepared.push({ target: item.absolute, temp, expectedHash: item.proposedHash });
      }
    } catch {
      for (const item of prepared) { try { fs.rmSync(item.temp, { force: true }); } catch { /* cleanup is best effort */ } }
      record.status = 'apply_failed'; record.updatedAt = now(); return err('INTERNAL_ERROR', 'Remediation preparation failed and no files were changed.');
    }
    record.status = 'prepared'; record.updatedAt = now();
    for (const item of checked) {
      let current: Buffer;
      try { current = fs.readFileSync(item.absolute); } catch { for (const preparedFile of prepared) { try { fs.rmSync(preparedFile.temp, { force: true }); } catch { /* ignore */ } } record.status = 'apply_failed'; record.updatedAt = now(); return err('REMEDIATION_CONFLICT', `Target file "${item.change.path}" changed before commit.`); }
      if (sha256(current) !== item.change.originalContentHash) {
        for (const preparedFile of prepared) { try { fs.rmSync(preparedFile.temp, { force: true }); } catch { /* ignore */ } }
        record.status = 'apply_failed'; record.updatedAt = now(); return err('REMEDIATION_CONFLICT', `Target file "${item.change.path}" changed before commit.`);
      }
    }
    record.status = 'committing'; record.appliedContentHashes = Object.fromEntries(checked.map((item) => [item.change.path, item.proposedHash]));
    const committed: typeof prepared = [];
    try {
      for (const item of prepared) {
        const change = record.proposal.files.find((candidate) => resolveWithinRoot(config.projectRoot, candidate.path) === item.target);
        if (!change || resolveExistingWithinRoot(config.projectRoot, change.path) !== item.target || sha256(fs.readFileSync(item.target)) !== change.originalContentHash) throw new Error('target changed before commit');
        fs.renameSync(item.temp, item.target); committed.push(item);
      }
      for (const item of committed) if (sha256(fs.readFileSync(item.target)) !== item.expectedHash) throw new Error('post-commit hash verification failed');
    } catch {
      for (const item of prepared) { try { fs.rmSync(item.temp, { force: true }); } catch { /* ignore */ } }
      let canRestore = true;
      for (const item of committed) { try { if (sha256(fs.readFileSync(item.target)) !== item.expectedHash) canRestore = false; } catch { canRestore = false; } }
      if (canRestore) {
        try { for (const snapshot of record.snapshots) fs.writeFileSync(resolveWithinRoot(config.projectRoot, snapshot.path), snapshot.originalContent, 'utf8'); } catch { canRestore = false; }
      }
      record.status = canRestore ? 'apply_failed' : 'rollback_required'; record.updatedAt = now();
      return err('INTERNAL_ERROR', canRestore ? 'Post-commit integrity verification failed; the snapshot was restored.' : 'Post-commit integrity verification failed and rollback was blocked by an external change.');
    }
    record.status = 'applied_pending_verification'; record.updatedAt = now();
    record.updatedAt = now();
    return ok(safeRecord(record));
  });
}

function relatedFinding(finding: InvestigationFinding, candidate: InvestigationFinding): boolean {
  return finding.category === candidate.category || (finding.candidateType === candidate.candidateType && Boolean(finding.path) && finding.path === candidate.path);
}

export async function verifyRemediation(config: AppConfig, remediationId: string): Promise<ToolOutcome<RemediationRecord>> {
  const existing = records.get(remediationId);
  if (!existing) return err('REMEDIATION_NOT_FOUND', `Remediation "${remediationId}" was not found.`);
  return withLock(lockKey(existing), async () => {
    const record = records.get(remediationId)!;
    if (record.status !== 'applied_pending_verification' && record.status !== 'verification_inconclusive' && record.status !== 'changed_finding' && record.status !== 'still_vulnerable') return err('INVALID_TRANSITION', `Remediation cannot be verified from status "${record.status}".`);
    record.status = 'verifying'; record.updatedAt = now();
    const before = currentInvestigation(record.proposal.investigationId);
    if (!before.ok) return before;
    const started = startInvestigation(config, { projectPath: config.projectRoot, scope: before.data.scope, hypothesis: `Re-analysis for remediation ${remediationId}` });
    if (!started.ok) return started;
    const analyzed = await runSecurityAnalysis(config, started.data.id);
    if (!analyzed.ok) { record.status = analyzed.error.code === 'BUDGET_EXCEEDED' ? 'verification_blocked' : 'verification_inconclusive'; return err(analyzed.error.code, analyzed.error.message); }
    const after = getInvestigation(started.data.id); if (!after.ok) return after;
    const originalFinding = findingFor(before.data, record.proposal.findingId)!;
    const related = after.data.findings.filter((finding) => relatedFinding(originalFinding, finding));
    const originalPresent = after.data.findings.some((finding) => finding.findingId === record.proposal.findingId);
    let runtimeStatus: string | null = null;
    let runtimeReceiptId: string | null = null;
    if (record.proposal.requiresRuntimeVerification && record.proposal.runtimeVerification) {
      if (originalFinding.origin === 'security_scan') {
        const priorReceipt = listSecurityReceiptsForFinding(record.proposal.findingId).find((receipt) => receipt.status === 'verified');
        if (!priorReceipt) {
          record.status = 'verification_inconclusive';
          record.updatedAt = now();
          return err('VERIFICATION_INCONCLUSIVE', 'A verified source proof receipt is required before remediation re-verification can replay the original proof.');
        }
        const replay = await replaySecurityProof(config, record.proposal.runtimeVerification, priorReceipt, remediationId);
        if (!replay.ok) { record.status = 'verification_inconclusive'; record.updatedAt = now(); return err(replay.error.code, replay.error.message); }
        runtimeStatus = replay.data.status;
        runtimeReceiptId = replay.data.receiptId;
      } else {
        const runtime = await verifyFinding(config, record.proposal.runtimeVerification);
        if (!runtime.ok) { record.status = runtime.error.code === 'TARGET_BLOCKED' ? 'verification_blocked' : 'verification_inconclusive'; return err(runtime.error.code, runtime.error.message); }
        runtimeStatus = runtime.data.result.status;
      }
    }
    const status: RemediationLifecycle = originalPresent ? 'still_vulnerable' : related.length > 0 ? 'changed_finding' : record.proposal.requiresRuntimeVerification && runtimeStatus !== 'verified' ? 'verification_inconclusive' : 'verified_resolved';
    const verification: RemediationVerification = { status, beforeFindingId: record.proposal.findingId, afterInvestigationId: after.data.id, staticFindingPresent: originalPresent, relatedFindings: related.map((finding) => ({ findingId: finding.findingId, title: finding.title, category: finding.category, path: finding.path, file: finding.file })), runtimeStatus, runtimeReceiptId, summary: originalPresent ? 'The original finding remains after deterministic re-analysis.' : related.length > 0 ? 'The original finding changed or a related security finding was introduced.' : status === 'verified_resolved' ? 'The original finding was absent after deterministic re-analysis and its verified proof no longer reproduced.' : 'Static re-analysis did not establish a verified resolution.', verifiedAt: now() };
    record.verification = verification; record.status = status; record.updatedAt = now(); return ok(safeRecord(record));
  });
}

export async function rollbackRemediation(config: AppConfig, remediationId: string): Promise<ToolOutcome<RemediationRecord>> {
  const existing = records.get(remediationId); if (!existing) return err('REMEDIATION_NOT_FOUND', `Remediation "${remediationId}" was not found.`);
  return withLock(lockKey(existing), async () => {
    const record = records.get(remediationId)!;
    if (record.status === 'rolled_back') return err('INVALID_TRANSITION', 'This remediation has already been rolled back.');
    if (record.snapshots.length === 0 || Object.keys(record.appliedContentHashes).length !== record.snapshots.length) return err('REMEDIATION_INVALID', 'No complete remediation snapshot is available for rollback.');
    for (const snapshot of record.snapshots) {
      let absolute: string;
      try { absolute = resolveExistingWithinRoot(config.projectRoot, snapshot.path); } catch { return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" is no longer safely inside the project root.`); }
      let current: Buffer;
      try { if (fs.lstatSync(absolute).isSymbolicLink()) return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" is now a symbolic link.`); current = fs.readFileSync(absolute); } catch { return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" is unavailable for rollback.`); }
      if (sha256(current) !== record.appliedContentHashes[snapshot.path]) return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" no longer matches the expected post-remediation hash.`);
    }
    try { for (const snapshot of record.snapshots) fs.writeFileSync(resolveExistingWithinRoot(config.projectRoot, snapshot.path), snapshot.originalContent, 'utf8'); } catch { record.status = 'rollback_required'; record.updatedAt = now(); return err('INTERNAL_ERROR', 'Rollback failed while restoring the snapshot.'); }
    for (const snapshot of record.snapshots) { const current = fs.readFileSync(resolveExistingWithinRoot(config.projectRoot, snapshot.path), 'utf8'); if (sha256(current) !== snapshot.originalContentHash) { record.status = 'rollback_required'; record.updatedAt = now(); return err('ROLLBACK_CONFLICT', `Restored hash verification failed for "${snapshot.path}".`); } }
    record.status = 'rolled_back'; record.updatedAt = now(); return ok(safeRecord(record));
  });
}

export function resetRemediationsForTests(): void { records.clear(); locks.clear(); }
