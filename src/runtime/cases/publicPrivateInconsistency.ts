import type { AccessControlFinding } from '../../access/types.js';
import type { AttackSurfaceEntry } from '../../routes/types.js';
import { issueRuntimeRequest, RuntimeClientState } from '../httpClient.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from '../types.js';
import { blockedResult, buildResult, hasUnresolvedSegment, isAuthRejection, isSuccessStatus } from './common.js';

/**
 * Case 5: Public/private inconsistency.
 *
 * Compares an unauthenticated request against an authenticated one for a
 * route Phase 5 indicates should be protected. Unlike the single-request
 * cases, this one's verification condition is a genuine *comparison*
 * (status equivalence between the two responses), which is stronger
 * evidence than a bare 200 -- if the unauthenticated caller gets the exact
 * same status as the authenticated caller, and that status is not itself an
 * auth rejection, this is real evidence of inconsistent protection.
 */

export function buildPublicPrivateInconsistencyCase(
  finding: AccessControlFinding,
  entry: AttackSurfaceEntry,
  authenticatedSessionId: string
): VerificationCase {
  return {
    id: `VC-PUBLIC-PRIVATE-${finding.id}`,
    type: 'public_private_inconsistency',
    findingId: finding.id,
    routeId: entry.id,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    objective: `Compare unauthenticated vs. authenticated ("${authenticatedSessionId}") responses for ${entry.method} ${entry.path}, which static analysis indicates should be protected.`,
    preconditions: ['The route path must be fully concrete.', `"${authenticatedSessionId}" must be a configured authenticated test session.`],
    requiredSessions: [authenticatedSessionId],
    expectedSecureBehavior: 'The unauthenticated request should be rejected (401/403) while the authenticated request succeeds.',
    cleanupRequired: false,
    relatedCandidateType: 'missing_authentication',
  };
}

export async function runPublicPrivateInconsistencyCase(
  vcase: VerificationCase,
  authenticatedSessionId: string,
  target: RuntimeTarget,
  sessions: Map<string, TestSession>,
  state: RuntimeClientState
): Promise<VerificationResult> {
  const startedAt = new Date().toISOString();

  if (hasUnresolvedSegment(vcase.path)) {
    return blockedResult(vcase, `Route path "${vcase.path}" still contains an unresolved dynamic segment.`, startedAt);
  }

  const method = vcase.method === 'ALL' || vcase.method === 'unknown' ? 'GET' : vcase.method;
  const anonEvidence = await issueRuntimeRequest(target, sessions, { method, path: vcase.path, sessionId: null }, state);
  const authEvidence = await issueRuntimeRequest(target, sessions, { method, path: vcase.path, sessionId: authenticatedSessionId }, state);
  const evidence = [anonEvidence, authEvidence];

  if (anonEvidence.response.status === 0 || authEvidence.response.status === 0) {
    const failed = anonEvidence.response.status === 0 ? anonEvidence : authEvidence;
    return blockedResult(vcase, failed.note.replace(/^Blocked:\s*/, ''), startedAt, evidence);
  }

  const anonStatus = anonEvidence.response.status;
  const authStatus = authEvidence.response.status;

  if (isAuthRejection(anonEvidence.response) && !isAuthRejection(authEvidence.response)) {
    return buildResult(
      vcase,
      'not_reproduced',
      'high',
      `Unauthenticated request received ${anonStatus} while the authenticated request received ${authStatus}. The route consistently distinguishes authenticated from unauthenticated callers; finding not reproduced.`,
      evidence,
      startedAt
    );
  }

  const equivalentResponse =
    anonStatus === authStatus &&
    anonEvidence.response.bodySnippet.length > 0 &&
    anonEvidence.response.bodySnippet === authEvidence.response.bodySnippet;
  if (!isAuthRejection(anonEvidence.response) && isSuccessStatus(authEvidence.response) && equivalentResponse) {
    return buildResult(
      vcase,
      'verified',
      'high',
      `Unauthenticated and authenticated requests received the same status ${anonStatus} and identical bounded response content for ${method} ${vcase.path}. The route does not distinguish between authenticated and unauthenticated callers, confirming the public/private inconsistency.`,
      evidence,
      startedAt
    );
  }

  return buildResult(
    vcase,
    'inconclusive',
    'medium',
    `Unauthenticated request received ${anonStatus} and authenticated request received ${authStatus}; the bounded response content did not establish an equivalent protected operation. This is inconclusive.`,
    evidence,
    startedAt
  );
}
