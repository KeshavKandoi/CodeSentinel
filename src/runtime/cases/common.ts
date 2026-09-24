import type { Confidence } from '../../discovery/types.js';
import type { RuntimeResponse, VerificationCase, VerificationEvidence, VerificationResult, VerificationStatus } from '../types.js';

/**
 * Deterministic, code-evaluated helpers shared by every verification case.
 * No case file is permitted to ask an LLM whether a response "looks"
 * vulnerable -- every verification condition here is a plain boolean
 * expression over status codes and response shape.
 */

export function isAuthRejection(response: RuntimeResponse): boolean {
  return response.status === 401 || response.status === 403;
}

export function isSuccessStatus(response: RuntimeResponse): boolean {
  return response.status >= 200 && response.status < 300;
}

export function isServerError(response: RuntimeResponse): boolean {
  return response.status >= 500;
}

export function isNotFound(response: RuntimeResponse): boolean {
  return response.status === 404;
}

export function buildResult(
  vcase: VerificationCase,
  status: VerificationStatus,
  confidence: Confidence,
  summary: string,
  evidence: VerificationEvidence[],
  startedAt: string,
  blockedReason: string | null = null
): VerificationResult {
  return {
    caseId: vcase.id,
    caseType: vcase.type,
    findingId: vcase.findingId,
    routeId: vcase.routeId,
    status,
    confidence,
    summary,
    evidence,
    requestsIssued: evidence.length,
    startedAt,
    finishedAt: new Date().toISOString(),
    blockedReason,
  };
}

export function blockedResult(
  vcase: VerificationCase,
  reason: string,
  startedAt: string,
  evidence: VerificationEvidence[] = []
): VerificationResult {
  return buildResult(vcase, 'blocked', 'low', `Verification blocked: ${reason}`, evidence, startedAt, reason);
}

/** True when a path still has an unresolved dynamic segment (":id", "{id}",
 * "<int:id>") that the caller must have concretized before a real request
 * can be sent against it. Verification never guesses a resource id. */
export function hasUnresolvedSegment(path: string): boolean {
  return /[:{<]/.test(path);
}
