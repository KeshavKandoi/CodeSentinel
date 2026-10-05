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
import type { RemediationFileChange, RemediationLifecycle, RemediationProposal, RemediationRecord, RemediationSnapshot, RemediationVerification, ReplayResult } from './types.js';
import { verifyFinding } from '../runtime/engine.js';
import { linkSecurityReceiptToRemediation, listSecurityReceiptsForFinding, replaySecurityProof } from '../proof/engine.js';
import { listFiles } from '../fs/fsOperations.js';

const MAX_FILE_BYTES = 1_000_000;
const MAX_TOTAL_BYTES = 2_000_000;
const MAX_RECORDS = 100;
const records = new Map<string, RemediationRecord>();
const locks = new Map<string, Promise<void>>();
const FORBIDDEN = /(^|\/)(\.env(?:\..*)?|\.ssh|credentials?|id_rsa|.*\.(?:pem|key|p12|pfx))$/i;

function sha256(content: string | Buffer): string { return crypto.createHash('sha256').update(content).digest('hex'); }
function now(): string { return new Date().toISOString(); }
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

const MAX_CHANGED_LINES = 500;
const MAX_REPORTED_CHANGES = 50;

interface TreeSnapshot { hashes: Map<string, string>; truncated: boolean; }

function deterministicId(input: ProposeRemediationInput): string {
  const canonical = JSON.stringify({ findingId: input.findingId, description: input.description, rationale: input.rationale, expectedSecurityEffect: input.expectedSecurityEffect, requiresRuntimeVerification: input.requiresRuntimeVerification, files: input.files.map((file) => ({ path: file.path, originalContentHash: file.originalContentHash, proposedHash: sha256(file.proposedContent), description: file.description })).sort((a, b) => a.path.localeCompare(b.path)) });
  return `remediation-${sha256(canonical).slice(0, 32)}`;
}

function remediationTypeFor(finding: InvestigationFinding): string {
  return finding.origin === 'security_scan' ? `source_${finding.category}` : `access_${finding.candidateType}`;
}

function changedLines(before: string, after: string): number {
  const a = before.split('\n');
  const b = after.split('\n');
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
  return (endA - start) + (endB - start);
}

function treeSnapshot(config: AppConfig): TreeSnapshot {
  const hashes = new Map<string, string>();
  const listed = listFiles(config, { dirPath: '.', recursive: true, maxResults: config.maxListResults });
  if (!listed.ok) return { hashes, truncated: true };
  const root = fs.realpathSync(config.projectRoot);
  for (const entry of listed.data) {
    if (entry.type !== 'file') continue;
    try {
      const absolute = path.join(root, entry.path);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) { hashes.set(entry.path, 'symlink'); continue; }
      hashes.set(entry.path, stat.size > MAX_FILE_BYTES ? `size:${stat.size}` : sha256(fs.readFileSync(absolute)));
    } catch {
      hashes.set(entry.path, 'unreadable');
    }
  }
  return { hashes, truncated: listed.data.length >= config.maxListResults };
}

function fingerprint(entries: Array<[string, string]>): string {
  return sha256(entries.map(([file, digest]) => `${file}|${digest}`).sort().join('\n'));
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
  let aliased = false;
  try { const lexical = path.join(fs.realpathSync(config.projectRoot), change.path); aliased = fs.realpathSync(lexical) !== lexical; } catch { return err('NOT_FOUND', `Remediation file ${change.path} could not be resolved.`); }
  if (aliased) return invalid(`Remediation path ${change.path} resolves through a symbolic link or path alias.`);
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
function currentInvestigation(config: AppConfig, id: string): ToolOutcome<SecurityInvestigation> {
  const result = getInvestigation(id);
  if (!result.ok) return result;
  if (path.resolve(result.data.projectPath) !== path.resolve(config.projectRoot)) return err('PATH_OUTSIDE_ROOT', 'The remediation belongs to another project root.');
  return result;
}

function freezeProposal(proposal: RemediationProposal): RemediationProposal {
  for (const file of proposal.files) Object.freeze(file);
  if (proposal.runtimeVerification) Object.freeze(proposal.runtimeVerification);
  return Object.freeze(proposal);
}

export async function proposeRemediation(config: AppConfig, input: ProposeRemediationInput): Promise<ToolOutcome<RemediationProposal>> {
  return withLock(proposalLockKey(input), async () => {
    const investigationResult = currentInvestigation(config, input.investigationId);
    if (!investigationResult.ok) return investigationResult;
    const investigation = investigationResult.data;
    const finding = findingFor(investigation, input.findingId);
    if (!finding) return err('REPORT_FINDING_NOT_FOUND', `Finding "${input.findingId}" was not found in investigation "${input.investigationId}".`);
    if (investigation.status !== 'completed' && investigation.status !== 'awaiting_verification') return err('INVESTIGATION_INCOMPLETE', 'Remediation requires a completed or verification-ready investigation.');
    if (input.files.some((file, index) => input.files.findIndex((other) => other.path === file.path) !== index)) return invalid('A remediation proposal cannot contain duplicate file paths.');
    const total = input.files.reduce((sum, file) => sum + Buffer.byteLength(file.proposedContent, 'utf8'), 0);
    if (total > MAX_TOTAL_BYTES) return invalid('The remediation proposal exceeds the total size bound.');
    let totalChangedLines = 0;
    for (const file of input.files) {
      const checked = validateFile(config, file);
      if (!checked.ok) return checked;
      if (sha256(checked.data.content) !== file.originalContentHash) return err('REMEDIATION_CONFLICT', `Original hash mismatch for "${file.path}"; the proposal is stale.`);
      totalChangedLines += changedLines(checked.data.content, file.proposedContent);
      if (totalChangedLines > MAX_CHANGED_LINES) return invalid(`The remediation proposal changes more than ${MAX_CHANGED_LINES} lines.`);
    }
    const duplicate = [...records.values()].find((record) => proposalLockKey(record.proposal as ProposeRemediationInput) === proposalLockKey(input));
    if (duplicate) return err('DUPLICATE_OPERATION', `An identical remediation proposal already exists as "${duplicate.proposal.proposalId}".`);
    if (input.runtimeVerification && input.runtimeVerification.findingId !== input.findingId) return invalid('runtimeVerification.findingId must match findingId.');
    const proposalId = deterministicId(input);
    if (records.has(proposalId)) return err('DUPLICATE_OPERATION', `An identical remediation proposal already exists as "${proposalId}".`);
    const proposal = freezeProposal({ proposalId, ...input, files: input.files.map((file) => ({ ...file })), remediationType: remediationTypeFor(finding), findingFile: finding.file, findingRoute: finding.path, createdAt: now() });
    const record: RemediationRecord = { proposal, status: 'validated', appliedAt: null, integrity: null, changeSummary: `Proposes changes to ${proposal.files.map((file) => file.path).sort().join(', ')}`.slice(0, 1000), snapshots: [], appliedContentHashes: {}, verification: null, updatedAt: now() };
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
    const investigation = currentInvestigation(config, record.proposal.investigationId);
    if (!investigation.ok) return investigation;
    if (!findingFor(investigation.data, record.proposal.findingId)) return err('REPORT_FINDING_NOT_FOUND', `Finding "${record.proposal.findingId}" is no longer present in the authorized investigation.`);
    const checked: Array<{ change: RemediationFileChange; absolute: string; content: string; proposedHash: string; mode: number }> = [];
    for (const change of record.proposal.files) {
      const result = validateFile(config, change); if (!result.ok) return result;
      if (sha256(result.data.content) !== change.originalContentHash) return err('REMEDIATION_CONFLICT', `Original hash mismatch for "${change.path}"; no files were changed.`);
      checked.push({ change, absolute: result.data.absolute, content: result.data.content, proposedHash: sha256(change.proposedContent), mode: fs.statSync(result.data.absolute).mode });
    }
    const treeBefore = treeSnapshot(config);
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
      for (const item of prepared) { try { fs.rmSync(item.temp, { force: true }); } catch {  } }
      record.status = 'apply_failed'; record.updatedAt = now(); return err('INTERNAL_ERROR', 'Remediation preparation failed and no files were changed.');
    }
    record.status = 'prepared'; record.updatedAt = now();
    for (const item of checked) {
      let current: Buffer;
      try { current = fs.readFileSync(item.absolute); } catch { for (const preparedFile of prepared) { try { fs.rmSync(preparedFile.temp, { force: true }); } catch {  } } record.status = 'apply_failed'; record.updatedAt = now(); return err('REMEDIATION_CONFLICT', `Target file "${item.change.path}" changed before commit.`); }
      if (sha256(current) !== item.change.originalContentHash) {
        for (const preparedFile of prepared) { try { fs.rmSync(preparedFile.temp, { force: true }); } catch {  } }
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
      for (const item of prepared) { try { fs.rmSync(item.temp, { force: true }); } catch {  } }
      let canRestore = true;
      for (const item of committed) { try { if (sha256(fs.readFileSync(item.target)) !== item.expectedHash) canRestore = false; } catch { canRestore = false; } }
      if (canRestore) {
        try { for (const snapshot of record.snapshots) fs.writeFileSync(resolveWithinRoot(config.projectRoot, snapshot.path), snapshot.originalContent, 'utf8'); } catch { canRestore = false; }
      }
      record.status = canRestore ? 'apply_failed' : 'rollback_required'; record.updatedAt = now();
      return err('INTERNAL_ERROR', canRestore ? 'Post-commit integrity verification failed; the snapshot was restored.' : 'Post-commit integrity verification failed and rollback was blocked by an external change.');
    }
    const treeAfter = treeSnapshot(config);
    const changedSet = new Set<string>();
    for (const [file, digest] of treeAfter.hashes) if (treeBefore.hashes.get(file) !== digest) changedSet.add(file);
    for (const file of treeBefore.hashes.keys()) if (!treeAfter.hashes.has(file)) changedSet.add(file);
    const changedFiles = [...changedSet].sort();
    const expectedChanged = checked.filter((item) => item.proposedHash !== item.change.originalContentHash).map((item) => item.change.path).sort();
    if (changedFiles.join('\n') !== expectedChanged.join('\n')) {
      let restored = true;
      for (const snapshot of record.snapshots) { try { fs.writeFileSync(resolveWithinRoot(config.projectRoot, snapshot.path), snapshot.originalContent, 'utf8'); } catch { restored = false; } }
      record.status = restored ? 'apply_failed' : 'rollback_required'; record.updatedAt = now();
      return err('REMEDIATION_CONFLICT', restored ? 'An unexpected source-tree change was detected during apply; the snapshot was restored.' : 'An unexpected source-tree change was detected during apply and rollback was blocked.');
    }
    const resulting = checked.map((item): [string, string] => [item.change.path, sha256(fs.readFileSync(item.absolute))]);
    record.integrity = Object.freeze({
      expectedSourceFingerprint: fingerprint(checked.map((item): [string, string] => [item.change.path, item.change.originalContentHash])),
      resultingFingerprint: fingerprint(resulting),
      treeFingerprintBefore: fingerprint([...treeBefore.hashes]),
      treeFingerprintAfter: fingerprint([...treeAfter.hashes]),
      changedFiles: changedFiles.slice(0, MAX_REPORTED_CHANGES),
      unchangedTargetFiles: checked.map((item) => item.change.path).filter((file) => !changedSet.has(file)).sort(),
      unchangedFileCount: [...treeAfter.hashes.keys()].filter((file) => !changedSet.has(file)).length,
      truncated: treeBefore.truncated || treeAfter.truncated,
    });
    record.appliedAt = now();
    record.changeSummary = `Changed ${changedFiles.length} file(s): ${checked.map((item) => `${item.change.path} (${changedLines(item.content, item.change.proposedContent)} line(s))`).sort().join(', ')}`.slice(0, 1000);
    record.status = 'applied_pending_verification'; record.updatedAt = now();
    const appliedFinding = findingFor(investigation.data, record.proposal.findingId);
    if (record.proposal.requiresRuntimeVerification && appliedFinding?.origin === 'security_scan') {
      const originalReceipt = listSecurityReceiptsForFinding(record.proposal.findingId, config.projectRoot).find((receipt) => receipt.status === 'verified');
      if (originalReceipt) linkSecurityReceiptToRemediation(record.proposal.findingId, originalReceipt.receiptId, remediationId, config.projectRoot);
    }
    record.updatedAt = now();
    return ok(safeRecord(record));
  });
}

function relatedFinding(finding: InvestigationFinding, candidate: InvestigationFinding): boolean {
  return finding.category === candidate.category || (finding.candidateType === candidate.candidateType && Boolean(finding.path) && finding.path === candidate.path);
}

export async function verifyRemediation(config: AppConfig, remediationId: string): Promise<ToolOutcome<RemediationRecord>> {
  try {
    return await verifyRemediationInner(config, remediationId);
  } catch {
    return err('INTERNAL_ERROR', 'Remediation verification failed unexpectedly.');
  }
}

async function guardVerification(remediationId: string, run: () => Promise<ToolOutcome<RemediationRecord>>): Promise<ToolOutcome<RemediationRecord>> {
  try {
    return await run();
  } catch {
    return err('INTERNAL_ERROR', 'Remediation verification failed unexpectedly.');
  } finally {
    const stuck = records.get(remediationId);
    if (stuck && stuck.status === 'verifying') { stuck.status = 'verification_inconclusive'; stuck.updatedAt = now(); }
  }
}

async function verifyRemediationInner(config: AppConfig, remediationId: string): Promise<ToolOutcome<RemediationRecord>> {
  const existing = records.get(remediationId);
  if (!existing) return err('REMEDIATION_NOT_FOUND', `Remediation "${remediationId}" was not found.`);
  return withLock(lockKey(existing), () => guardVerification(remediationId, async () => {
    const record = records.get(remediationId)!;
    const before = currentInvestigation(config, record.proposal.investigationId);
    if (!before.ok) return before;
    if (record.status !== 'applied_pending_verification' && record.status !== 'verification_inconclusive' && record.status !== 'changed_finding' && record.status !== 'still_vulnerable') return err('INVALID_TRANSITION', `Remediation cannot be verified from status "${record.status}".`);
    const drifted = Object.entries(record.appliedContentHashes).some(([file, expected]) => { try { return sha256(fs.readFileSync(resolveExistingWithinRoot(config.projectRoot, file))) !== expected; } catch { return true; } });
    if (drifted || record.integrity === null) {
      record.status = 'verification_inconclusive'; record.updatedAt = now();
      return err('VERIFICATION_INCONCLUSIVE', 'The applied files no longer match the recorded post-remediation fingerprint; verification cannot justify resolution.');
    }
    record.status = 'verifying'; record.updatedAt = now();
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
        const priorReceipt = listSecurityReceiptsForFinding(record.proposal.findingId, config.projectRoot).find((receipt) => receipt.status === 'verified');
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
        const originalOrigins = before.data.hypotheses
          .filter((hypothesis) => hypothesis.findingId === record.proposal.findingId)
          .map((hypothesis) => before.data.runtimeResults[hypothesis.id])
          .filter((result) => result !== undefined && result.status === 'verified')
          .map((result) => result.targetOrigin);
        if (!originalOrigins.includes(record.proposal.runtimeVerification.target.allowedOrigin)) {
          record.status = 'verification_inconclusive'; record.updatedAt = now();
          return err('VERIFICATION_INCONCLUSIVE', 'The replay target does not match the origin of the original verified runtime result.');
        }
        const runtime = await verifyFinding(config, record.proposal.runtimeVerification);
        if (!runtime.ok) { record.status = runtime.error.code === 'TARGET_BLOCKED' ? 'verification_blocked' : 'verification_inconclusive'; return err(runtime.error.code, runtime.error.message); }
        runtimeStatus = runtime.data.result.status;
      }
    }
    const originalVerified = originalFinding.lifecycle === 'runtime_verified' || listSecurityReceiptsForFinding(record.proposal.findingId, config.projectRoot).some((receipt) => receipt.status === 'verified' && receipt.replayOfReceiptId === null);
    const replaySafe = runtimeStatus === 'not_reproduced' && originalVerified;
    const replayResult: ReplayResult = originalPresent || runtimeStatus === 'verified' ? 'still_present' : runtimeStatus === 'blocked' ? 'blocked' : related.length === 0 && replaySafe && record.proposal.requiresRuntimeVerification ? 'resolved' : 'inconclusive';
    const status: RemediationLifecycle = originalPresent ? 'still_vulnerable' : related.length > 0 ? 'changed_finding' : !record.proposal.requiresRuntimeVerification ? 'verification_inconclusive' : !replaySafe ? 'verification_inconclusive' : 'verified_resolved';
    const verification: RemediationVerification = { status, beforeFindingId: record.proposal.findingId, afterInvestigationId: after.data.id, staticFindingPresent: originalPresent, relatedFindings: related.map((finding) => ({ findingId: finding.findingId, title: finding.title, category: finding.category, path: finding.path, file: finding.file })), runtimeStatus, runtimeReceiptId, replayResult, summary: originalPresent ? 'The original finding remains after deterministic re-analysis.' : related.length > 0 ? 'The original finding changed or a related security finding was introduced.' : status === 'verified_resolved' ? 'The original finding was absent after deterministic re-analysis and its verified proof no longer reproduced.' : 'Static re-analysis did not establish a verified resolution.', verifiedAt: now() };
    record.verification = verification; record.status = status; record.updatedAt = now(); return ok(safeRecord(record));
  }));
}

export async function rollbackRemediation(config: AppConfig, remediationId: string): Promise<ToolOutcome<RemediationRecord>> {
  const existing = records.get(remediationId); if (!existing) return err('REMEDIATION_NOT_FOUND', `Remediation "${remediationId}" was not found.`);
  return withLock(lockKey(existing), async () => {
    const record = records.get(remediationId)!;
    const investigation = currentInvestigation(config, record.proposal.investigationId);
    if (!investigation.ok) return investigation;
    if (record.status === 'rolled_back') return err('INVALID_TRANSITION', 'This remediation has already been rolled back.');
    if (record.snapshots.length === 0 || Object.keys(record.appliedContentHashes).length !== record.snapshots.length) return err('REMEDIATION_INVALID', 'No complete remediation snapshot is available for rollback.');
    for (const snapshot of record.snapshots) {
      let absolute: string;
      try { absolute = resolveExistingWithinRoot(config.projectRoot, snapshot.path); } catch { return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" is no longer safely inside the project root.`); }
      let current: Buffer;
      try { if (fs.lstatSync(absolute).isSymbolicLink()) return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" is now a symbolic link.`); current = fs.readFileSync(absolute); } catch { return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" is unavailable for rollback.`); }
      if (sha256(current) !== record.appliedContentHashes[snapshot.path]) return err('ROLLBACK_CONFLICT', `Current file "${snapshot.path}" no longer matches the expected post-remediation hash.`);
    }
    const restoreTargets: Array<{ snapshot: RemediationSnapshot; absolute: string; temp: string }> = [];
    try {
      for (const snapshot of record.snapshots) {
        const absolute = resolveExistingWithinRoot(config.projectRoot, snapshot.path);
        const temp = `${absolute}.codesentinel-rollback-${crypto.randomUUID()}.tmp`;
        fs.writeFileSync(temp, snapshot.originalContent, { encoding: 'utf8', flag: 'wx' });
        restoreTargets.push({ snapshot, absolute, temp });
        if (sha256(fs.readFileSync(temp)) !== snapshot.originalContentHash) throw new Error('rollback preparation hash mismatch');
      }
      for (const item of restoreTargets) fs.renameSync(item.temp, item.absolute);
    } catch {
      for (const item of restoreTargets) { try { fs.rmSync(item.temp, { force: true }); } catch {  } }
      record.status = 'rollback_required'; record.updatedAt = now(); return err('INTERNAL_ERROR', 'Rollback failed while restoring the snapshot.');
    }
    for (const item of restoreTargets) { if (sha256(fs.readFileSync(item.absolute)) !== item.snapshot.originalContentHash) { record.status = 'rollback_required'; record.updatedAt = now(); return err('ROLLBACK_CONFLICT', `Restored hash verification failed for "${item.snapshot.path}".`); } }
    record.status = 'rolled_back'; record.updatedAt = now(); return ok(safeRecord(record));
  });
}

export function resetRemediationsForTests(): void { records.clear(); locks.clear(); }
