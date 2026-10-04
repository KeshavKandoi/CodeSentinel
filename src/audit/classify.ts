import { resolveProofSupport } from '../proof/engine.js';
import type { AttackSurfaceEntry } from '../routes/types.js';
import { advance } from './lifecycle.js';
import type { AuditFinding, ProofClassification } from './types.js';

export function classifyFinding(finding: AuditFinding, routes?: readonly AttackSurfaceEntry[]): ProofClassification {
  let requiresAdapter = false;
  for (const source of finding.sources) {
    if (source.origin !== 'security_scan' && source.origin !== 'access_control') continue;
    const resolution = resolveProofSupport({ origin: source.origin, category: source.category, candidateType: source.candidateType ?? '', ruleId: source.ruleId });
    if (resolution.supportClass === 'runtime') {
      const base = { proofSupport: 'runtime' as const, adapter: resolution.adapterType, proofSourceId: source.sourceId, prerequisites: resolution.prerequisites, maxRequests: resolution.maxRequests };
      if (source.origin === 'security_scan' && routes !== undefined && !routes.some((entry) => entry.file === finding.file && finding.line !== null && finding.line >= entry.sourceRange.startLine && finding.line <= entry.sourceRange.endLine)) {
        return { ...base, proofStatus: 'blocked', reason: 'No discovered route contains this source location; runtime proof requires a concrete route.' };
      }
      if (source.origin === 'access_control' && source.routePath === 'unknown') {
        return { ...base, proofStatus: 'blocked', reason: 'The route path could not be resolved statically; runtime proof requires a known route.' };
      }
      return { ...base, proofStatus: 'eligible', reason: 'A registered proof adapter handles this finding class; execution still requires an operator-authorized local target.' };
    }
    if (resolution.supportClass === 'requires-adapter') requiresAdapter = true;
  }
  if (requiresAdapter) {
    return { proofSupport: 'requires-adapter', proofStatus: 'unsupported', adapter: null, proofSourceId: null, prerequisites: [], maxRequests: 0, reason: 'This finding class has a defined proof type but no executable adapter is registered.' };
  }
  return { proofSupport: 'static-only', proofStatus: 'unsupported', adapter: null, proofSourceId: null, prerequisites: [], maxRequests: 0, reason: 'No executable proof adapter exists for this finding class; it remains a static candidate.' };
}

export function applyClassification(finding: AuditFinding, routes?: readonly AttackSurfaceEntry[]): void {
  finding.classification = classifyFinding(finding, routes);
  const status = finding.classification.proofStatus;
  advance(finding, status === 'eligible' ? 'proof_eligible' : status === 'blocked' ? 'blocked' : 'unsupported');
}
