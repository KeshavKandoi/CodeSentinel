import crypto from 'node:crypto';
import fs from 'node:fs';
import type { AppConfig } from '../config.js';
import { openRegularFileWithinRoot, resolveExistingWithinRoot } from '../fs/pathGuard.js';
import { err, ok, type ToolOutcome } from '../types.js';
import { scanProject } from '../security/scanner.js';
import type { SecurityFinding } from '../security/types.js';
import { discoverRoutes } from '../routes/engine.js';
import { analyzeAccessControl } from '../access/engine.js';
import type { AccessControlFinding } from '../access/types.js';
import { fromAccessFinding, fromSecurityFinding } from '../audit/identity.js';
import { listSecurityReceiptsForFinding, proveSecurityFinding, replaySecurityProof } from '../proof/engine.js';
import type { SecurityReceipt } from '../proof/types.js';
import type { RuntimeTarget, TestSession } from '../runtime/types.js';
import { MISSING_RUNTIME_TARGET } from '../audit/environment.js';
import { getControlledRemediationRecord, type ControlledBeforeFinding } from './engine.js';

export type RetestResult = 'resolved' | 'still_present' | 'inconclusive' | 'blocked' | 'not_verifiable';
export interface RetestFindingInput {
  findingId: string;
  target?: RuntimeTarget;
  sessions?: TestSession[];
  sessionParams?: Record<string, string>;
}
export interface RetestFindingReceipt {
  findingId: string;
  remediationId: string;
  projectRoot: string;
  retestStatus: 'completed' | 'blocked' | 'failed';
  result: RetestResult;
  securityStatus: 'finding_resolved' | 'finding_present' | 'inconclusive';
  executionStatus: 'completed' | 'blocked' | 'failed';
  verification: { attempted: boolean; completed: boolean; verified: boolean; blocked: boolean };
  before: ControlledBeforeFinding & { status: 'present' | 'unverified_baseline' };
  after: { status: 'present' | 'absent' | 'unknown'; findingId: string | null; ruleId: string | null; file: string; line: number | null; severity: string | null; confidence: string | null; evidenceHash: string | null };
  evidence: { method: 'static_rule_retest' | 'runtime_proof_replay' | 'runtime_proof' | 'unsupported'; filesChecked: number; proofReceiptId: string | null; originalReceiptId: string | null };
  blocker: { kind: string; responsibility: string; reason: string; recommendedNextStep: string } | null;
  timestamp: string;
  limitation: string | null;
}

function hash(value: string | Buffer): string { return crypto.createHash('sha256').update(value).digest('hex'); }

function currentFileHash(config: AppConfig, file: string): string | null {
  let absolute: string;
  try { absolute = resolveExistingWithinRoot(config.projectRoot, file); } catch { return null; }
  const opened = openRegularFileWithinRoot(config.projectRoot, absolute);
  if (!opened.ok) return null;
  try {
    if (opened.size > 1_000_000) return null;
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(opened.fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) return null;
      offset += count;
    }
    return hash(bytes);
  } catch { return null; } finally { fs.closeSync(opened.fd); }
}

function sameCondition<T extends SecurityFinding>(before: ControlledBeforeFinding, candidates: T[]): T | null | 'ambiguous' {
  const exact = candidates.find((item) => item.id === before.sourceId);
  if (exact) return exact;
  const evidence = candidates.filter((item) => hash(item.evidence.map((part) => part.matchedText ?? part.reason).join('|')) === before.evidenceHash);
  if (evidence.length === 1) return evidence[0];
  return candidates.length === 0 ? null : 'ambiguous';
}

export async function retestFinding(config: AppConfig, input: RetestFindingInput): Promise<ToolOutcome<RetestFindingReceipt>> {
  const record = getControlledRemediationRecord(config.projectRoot, input.findingId);
  if (!record) return err('REMEDIATION_NOT_FOUND', 'No validated controlled remediation is recorded for this finding and canonical project root.');
  const before = record.before;
  const response: RetestFindingReceipt = {
    findingId: record.findingId, remediationId: record.remediationId, projectRoot: config.projectRoot,
    retestStatus: 'completed', result: 'inconclusive', securityStatus: 'inconclusive', executionStatus: 'completed',
    verification: { attempted: false, completed: false, verified: false, blocked: false },
    before: { ...before, status: before.origin === 'unsupported' ? 'unverified_baseline' : 'present' },
    after: { status: 'unknown', findingId: null, ruleId: before.ruleId, file: before.file, line: null, severity: null, confidence: null, evidenceHash: null },
    evidence: { method: 'unsupported', filesChecked: 0, proofReceiptId: null, originalReceiptId: before.originalReceiptId },
    blocker: null, timestamp: new Date().toISOString(), limitation: null,
  };
  const initialHash = currentFileHash(config, record.file);
  if (!initialHash || initialHash !== record.appliedHash) {
    response.retestStatus = 'failed'; response.executionStatus = 'failed';
    response.limitation = 'The remediated file changed after validation or could not be read safely; a new baseline is required.';
    return ok(response);
  }
  if (before.origin === 'unsupported' || before.proofSupport === 'requires-adapter') {
    response.result = 'not_verifiable';
    response.limitation = 'The original finding has no supported, evidence-backed verification method.';
    return ok(response);
  }
  let match: SecurityFinding | AccessControlFinding | null | 'ambiguous' = null;
  if (before.origin === 'security_scan') {
    const scan = await scanProject(config);
    if (!scan.ok || !before.ruleId || !scan.data.rulesRun.includes(before.ruleId) || scan.data.rulesFailed.some((item) => item.ruleId === before.ruleId) || scan.data.fileAnalysis.inventoryTruncated || scan.data.fileAnalysis.skippedFiles.some((item) => item.file === before.file)) {
      response.limitation = 'The original static rule or file was not completely analyzed during retest.';
      return ok(response);
    }
    const candidates = scan.data.findings.filter((item) => item.ruleId === before.ruleId && item.file === before.file && item.category === before.category);
    match = sameCondition(before, candidates);
    response.evidence.method = 'static_rule_retest'; response.evidence.filesChecked = 1;
  } else {
    const routes = discoverRoutes(config);
    if (!routes.ok) { response.limitation = 'Route discovery was unavailable during retest.'; return ok(response); }
    const access = analyzeAccessControl(config, routes.data.entries);
    const candidates = access.findings.filter((item) => item.file === before.file && item.candidateType === before.candidateType && item.path === before.route);
    match = sameCondition(before, candidates);
    response.evidence.method = 'static_rule_retest'; response.evidence.filesChecked = 1;
  }
  if (match === 'ambiguous' && before.proofSupport !== 'runtime') { response.limitation = 'Current findings share the original class and file but could not be matched to the original condition safely.'; return ok(response); }
  if (match && match !== 'ambiguous') {
    response.after = { status: 'present', findingId: match.id, ruleId: match.ruleId, file: match.file ?? before.file, line: match.line ?? null, severity: match.severity, confidence: match.confidence, evidenceHash: hash(match.evidence.map((item) => item.matchedText ?? item.reason).join('|')) };
  } else if (match === null) response.after.status = 'absent';
  if (before.proofSupport !== 'runtime') {
    response.verification = { attempted: true, completed: true, verified: !match, blocked: false };
    response.result = match ? 'still_present' : 'resolved';
    response.securityStatus = match ? 'finding_present' : 'finding_resolved';
  } else if (!input.target) {
    response.retestStatus = 'blocked'; response.executionStatus = 'blocked'; response.result = 'inconclusive';
    response.verification.blocked = true;
    response.blocker = { ...MISSING_RUNTIME_TARGET, recommendedNextStep: 'Provide an authorized isolated local runtime target and rerun the retest.' };
  } else {
    let proof: ToolOutcome<SecurityReceipt> | null = null;
    if (before.originalReceiptId && before.sourceId) {
      const original = listSecurityReceiptsForFinding(before.sourceId, config.projectRoot).find((item) => item.receiptId === before.originalReceiptId);
      if (original) proof = await replaySecurityProof(config, { findingId: before.sourceId, target: input.target, sessions: input.sessions ?? [], sessionParams: input.sessionParams ?? {} }, original, record.remediationId);
    }
    if ((!proof || !proof.ok) && match && match !== 'ambiguous') proof = await proveSecurityFinding(config, { findingId: match.id, target: input.target, sessions: input.sessions ?? [], sessionParams: input.sessionParams ?? {} });
    if (!proof || !proof.ok) {
      response.limitation = 'No supported proof could replay the original condition against the current target state.';
    } else {
      response.evidence.method = proof.data.replayOfReceiptId ? 'runtime_proof_replay' : 'runtime_proof';
      response.evidence.proofReceiptId = proof.data.receiptId;
      response.verification.attempted = true;
      if (proof.data.status === 'blocked') {
        response.retestStatus = 'blocked'; response.executionStatus = 'blocked'; response.verification.blocked = true;
        response.blocker = { kind: 'proof_prerequisite', responsibility: 'user_environment', reason: proof.data.limitation ?? 'The runtime proof was blocked.', recommendedNextStep: 'Check the isolated runtime target and proof prerequisites, then rerun the retest.' };
      } else if (proof.data.status === 'inconclusive') {
        response.verification.completed = true;
        response.limitation = proof.data.limitation ?? 'The runtime oracle was inconclusive.';
      } else if (proof.data.status === 'verified') {
        response.verification.completed = true;
        response.result = 'still_present'; response.securityStatus = 'finding_present';
      } else if (proof.data.status === 'not_reproduced' && before.originalReceiptId && proof.data.replayOfReceiptId === before.originalReceiptId && proof.data.targetOrigin === input.target.allowedOrigin) {
        response.verification.completed = true; response.verification.verified = true;
        response.result = 'resolved'; response.securityStatus = 'finding_resolved';
      } else {
        response.verification.completed = true;
        response.limitation = 'The proof did not reproduce, but no trusted original proof at the same target origin establishes a before/after comparison.';
      }
    }
  }
  const finalHash = currentFileHash(config, record.file);
  if (finalHash !== initialHash) {
    response.retestStatus = 'failed'; response.executionStatus = 'failed'; response.result = 'inconclusive'; response.securityStatus = 'inconclusive';
    response.verification.verified = false;
    response.limitation = 'The source file changed during retest; no security conclusion is reported.';
  }
  return ok(response);
}
