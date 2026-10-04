import type { SecurityReceipt } from '../proof/types.js';
import type { AuditFinding, FindingStatus } from './types.js';

const TRANSITIONS: Record<FindingStatus, readonly FindingStatus[]> = {
  candidate: ['analyzed', 'unsupported', 'blocked', 'inconclusive'],
  analyzed: ['proof_eligible', 'unsupported', 'blocked', 'inconclusive'],
  proof_eligible: ['verified', 'not_reproduced', 'inconclusive', 'blocked'],
  verified: ['remediation_applied'],
  remediation_applied: ['verified_resolved', 'verified', 'inconclusive', 'blocked'],
  not_reproduced: [],
  unsupported: [],
  blocked: [],
  inconclusive: [],
  verified_resolved: [],
};

export function canAdvance(from: FindingStatus, to: FindingStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

export function advance(finding: AuditFinding, to: FindingStatus): void {
  if (finding.status === to) return;
  if (!canAdvance(finding.status, to)) throw new Error(`Illegal finding transition ${finding.status} -> ${to}`);
  finding.status = to;
}

export function advanceToVerified(finding: AuditFinding, receipt: SecurityReceipt): void {
  const proven =
    receipt.status === 'verified' &&
    receipt.oracle === 'verified' &&
    receipt.whyProven.length > 0 &&
    receipt.proofCase.executable === true &&
    finding.classification.proofSupport === 'runtime' &&
    receipt.findingId === finding.classification.proofSourceId;
  if (!proven) throw new Error('Verification requires an executable-adapter receipt with a verified semantic oracle');
  advance(finding, 'verified');
}
