import type { AccessControlFinding } from '../../access/types.js';
import type { AttackSurfaceEntry } from '../../routes/types.js';
import { issueRuntimeRequest, RuntimeClientState } from '../httpClient.js';
import type { RuntimeTarget, TestSession, VerificationCase, VerificationResult } from '../types.js';
import { blockedResult, buildResult, hasUnresolvedSegment, isAuthRejection, isNotFound, isSuccessStatus } from './common.js';

/**
 * Case 4: Ownership candidate.
 *
 * Distinct from Case 2 (IDOR/BOLA -- "can a stranger reach this resource at
 * all") in intent: this case exists for routes Phase 5 classified as
 * ownership-relevant where the finding is about confirming ownership
 * restrictions are actually enforced end-to-end (used to positively confirm
 * `ownership_protected` classifications hold at runtime, not only to catch
 * their absence). Mechanically the request/response evaluation is the same
 * conservative shape as Case 2.
 */

export function buildOwnershipCase(
  finding: AccessControlFinding,
  entry: AttackSurfaceEntry,
  ownerSessionId: string,
  otherSessionId: string
): VerificationCase {
  return {
    id: `VC-OWNERSHIP-${finding.id}`,
    type: 'ownership',
    findingId: finding.id,
    routeId: entry.id,
    method: entry.method,
    path: entry.path,
    framework: entry.framework,
    objective: `Confirm ownership restrictions on ${entry.method} ${entry.path} are enforced: identity "${otherSessionId}" must not be able to act on a resource owned by "${ownerSessionId}".`,
    preconditions: [
      'The route path must reference a concrete, fixture-supplied resource id belonging to ownerSessionId.',
      `Both "${ownerSessionId}" and "${otherSessionId}" must be configured test sessions.`,
    ],
    requiredSessions: [ownerSessionId, otherSessionId],
    expectedSecureBehavior: `Identity "${otherSessionId}" should be rejected (401/403) or the resource should not be found (404).`,
    cleanupRequired: entry.method === 'DELETE',
    relatedCandidateType: 'user_resource_access',
  };
}

export async function runOwnershipCase(
  vcase: VerificationCase,
  otherSessionId: string,
  target: RuntimeTarget,
  sessions: Map<string, TestSession>,
  state: RuntimeClientState
): Promise<VerificationResult> {
  const startedAt = new Date().toISOString();

  if (hasUnresolvedSegment(vcase.path)) {
    return blockedResult(vcase, `Route path "${vcase.path}" still contains an unresolved dynamic segment.`, startedAt);
  }
  if (vcase.method === 'DELETE' && target.allowDestructiveMethods !== true) {
    return blockedResult(vcase, 'DELETE is a destructive method and allowDestructiveMethods is not enabled on the target.', startedAt);
  }

  const evidence = [
    await issueRuntimeRequest(target, sessions, { method: vcase.method, path: vcase.path, sessionId: otherSessionId }, state),
  ];
  const response = evidence[0]!.response;

  if (response.status === 0) {
    return blockedResult(vcase, evidence[0]!.note.replace(/^Blocked:\s*/, ''), startedAt, evidence);
  }

  if (isAuthRejection(response) || isNotFound(response)) {
    return buildResult(
      vcase,
      'not_reproduced',
      'high',
      `Identity "${otherSessionId}" received ${response.status}; ownership restriction holds at runtime. Finding not reproduced.`,
      evidence,
      startedAt
    );
  }

  const isWrite = vcase.method === 'POST' || vcase.method === 'PUT' || vcase.method === 'PATCH' || vcase.method === 'DELETE';
  if (isSuccessStatus(response) && isWrite) {
    return buildResult(
      vcase,
      'verified',
      'high',
      `Identity "${otherSessionId}" successfully performed ${vcase.method} ${vcase.path} (status ${response.status}) on a resource it does not own; ownership restriction does not hold at runtime.`,
      evidence,
      startedAt
    );
  }

  if (isSuccessStatus(response)) {
    return buildResult(
      vcase,
      'inconclusive',
      'medium',
      `Identity "${otherSessionId}" received ${response.status} reading the resource; consistent with a missing ownership check but not conclusive for a read alone.`,
      evidence,
      startedAt
    );
  }

  return buildResult(vcase, 'inconclusive', 'low', `Received an unexpected status ${response.status}.`, evidence, startedAt);
}
